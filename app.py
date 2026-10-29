"""
VaultX Password Manager
Flask entry point, database setup, page routes, and JSON APIs.

Run: python app.py
"""

import os
import json
import hmac
import secrets
import sqlite3
import string
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def load_flask_secret():
    """Load a stable local signing key, creating one if needed."""
    env_secret = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if env_secret:
        if len(env_secret) < 32:
            raise RuntimeError("FLASK_SECRET_KEY phải có ít nhất 32 ký tự.")
        return env_secret

    secret_path = os.path.join(os.path.dirname(__file__), ".flask_secret.key")
    try:
        with open(secret_path, "r", encoding="ascii") as secret_file:
            saved_secret = secret_file.read().strip()
            if len(saved_secret) < 32:
                raise RuntimeError(".flask_secret.key bị thiếu hoặc không hợp lệ.")
            return saved_secret
    except FileNotFoundError:
        generated = secrets.token_urlsafe(48)
        try:
            descriptor = os.open(secret_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            with open(secret_path, "r", encoding="ascii") as secret_file:
                saved_secret = secret_file.read().strip()
                if len(saved_secret) < 32:
                    raise RuntimeError(".flask_secret.key bị thiếu hoặc không hợp lệ.")
                return saved_secret
        with os.fdopen(descriptor, "w", encoding="ascii") as secret_file:
            secret_file.write(generated)
        return generated


app = Flask(__name__)
app.secret_key = load_flask_secret()
app.permanent_session_lifetime = timedelta(days=30)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"},
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

DATABASE = os.path.join(os.path.dirname(__file__), "vault.db")
ENTRY_CATEGORIES = {"login", "card", "note"}
KEY_FILE = os.path.join(os.path.dirname(__file__), ".vaultx.key")
ENCRYPTED_PREFIX = "vx1:"
SENSITIVE_FIELDS = (
    "username",
    "password",
    "notes",
    "card_number",
    "card_expiry",
    "card_cvv",
    "note_content",
)
_fernet = None


def utc_now():
    return datetime.utcnow().isoformat(timespec="seconds")


def load_encryption_key():
    env_key = os.environ.get("VAULTX_ENCRYPTION_KEY", "").strip()
    if env_key:
        return env_key.encode("ascii")

    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read().strip()

    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key


def get_fernet():
    global _fernet
    if _fernet is None:
        _fernet = Fernet(load_encryption_key())
    return _fernet


def is_encrypted_value(value):
    return isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX)


def encrypt_value(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    if not value or is_encrypted_value(value):
        return value
    token = get_fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return ENCRYPTED_PREFIX + token


def decrypt_value(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    if not is_encrypted_value(value):
        return value
    token = value[len(ENCRYPTED_PREFIX):].encode("ascii")
    try:
        return get_fernet().decrypt(token).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def encrypted_payload(payload):
    stored = payload.copy()
    for field in SENSITIVE_FIELDS:
        stored[field] = encrypt_value(stored.get(field))
    return stored


def decrypted_entry_dict(row):
    entry = dict(row)
    for field in SENSITIVE_FIELDS:
        entry[field] = decrypt_value(entry.get(field))
    return entry


def ensure_db():
    """Create tables and migrate older local databases in-place."""
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT DEFAULT '',
            username TEXT DEFAULT '',
            url TEXT DEFAULT '',
            password TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            category TEXT DEFAULT 'login',
            favorite INTEGER DEFAULT 0,
            card_name TEXT DEFAULT '',
            card_number TEXT DEFAULT '',
            card_expiry TEXT DEFAULT '',
            card_cvv TEXT DEFAULT '',
            note_title TEXT DEFAULT '',
            note_content TEXT DEFAULT '',
            deleted INTEGER DEFAULT 0,
            deleted_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    existing_columns = {row[1] for row in cursor.execute("PRAGMA table_info(entries)").fetchall()}
    migrations = {
        "favorite": "INTEGER DEFAULT 0",
        "card_name": "TEXT DEFAULT ''",
        "card_number": "TEXT DEFAULT ''",
        "card_expiry": "TEXT DEFAULT ''",
        "card_cvv": "TEXT DEFAULT ''",
        "note_title": "TEXT DEFAULT ''",
        "note_content": "TEXT DEFAULT ''",
    }
    for column, column_type in migrations.items():
        if column not in existing_columns:
            cursor.execute(f"ALTER TABLE entries ADD COLUMN {column} {column_type}")

    migrate_sensitive_fields(cursor)
    db.commit()
    db.close()


def migrate_sensitive_fields(cursor):
    # Older builds copied the card number into username as a display shortcut.
    # Remove that duplicate before encrypting any legacy values.
    cursor.execute("UPDATE entries SET username = '' WHERE category = 'card'")
    fields_sql = ", ".join(SENSITIVE_FIELDS)
    rows = cursor.execute(f"SELECT id, {fields_sql} FROM entries").fetchall()
    for row in rows:
        entry_id = row[0]
        updates = {}
        for index, field in enumerate(SENSITIVE_FIELDS, start=1):
            original = row[index] or ""
            encrypted = encrypt_value(original)
            if encrypted != original:
                updates[field] = encrypted
        if updates:
            set_clause = ", ".join(f"{field} = ?" for field in updates)
            params = list(updates.values()) + [entry_id]
            cursor.execute(f"UPDATE entries SET {set_clause} WHERE id = ?", params)


ensure_db()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def teardown_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


@app.before_request
def protect_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    expected = session.get("_csrf_token", "")
    provided = request.headers.get("X-CSRFToken") or request.form.get("csrf_token", "")
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        abort(400, description="Yêu cầu không hợp lệ. Vui lòng tải lại trang và thử lại.")


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.before_request
def load_current_user():
    g.user = None
    user_id = session.get("user_id")
    if not user_id:
        return

    user_row = query_db("SELECT id, first_name, last_name, email FROM users WHERE id = ?", (user_id,), one=True)
    if user_row:
        user = dict(user_row)
        user["name"] = f"{user_row['first_name']} {user_row['last_name']}".strip()
        initials = "".join(part[0] for part in [user_row["first_name"], user_row["last_name"]] if part)
        user["initials"] = initials.upper()[:2] or "VX"
        g.user = user


@app.context_processor
def inject_user():
    return {"current_user": g.user, "csrf_token": csrf_token}


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def clean_text(value):
    return (value or "").strip()


def normalize_category(category):
    return category if category in ENTRY_CATEGORIES else "login"


def password_strength(password):
    if not password:
        return {"key": "weak", "label": "Yếu", "score": 0}

    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(ch.islower() for ch in password) and any(ch.isupper() for ch in password):
        score += 1
    if any(ch.isdigit() for ch in password):
        score += 1
    if any(ch in string.punctuation for ch in password):
        score += 1

    if score >= 4:
        return {"key": "strong", "label": "Mạnh", "score": score}
    if score >= 2:
        return {"key": "medium", "label": "Trung bình", "score": score}
    return {"key": "weak", "label": "Yếu", "score": score}


def favicon_color(text):
    colors = ["#6366f1", "#0ea5e9", "#14b8a6", "#f59e0b", "#ef4444", "#8b5cf6", "#10b981"]
    seed = sum(ord(ch) for ch in (text or "VaultX"))
    return colors[seed % len(colors)]


def first_letter(text):
    for char in text or "":
        if char.isalnum():
            return char.upper()
    return "V"


def mask_card_number(number):
    digits = "".join(ch for ch in number or "" if ch.isdigit())
    if len(digits) <= 4:
        return digits or "Chưa có số thẻ"
    return f"•••• •••• •••• {digits[-4:]}"


def display_entry(row, include_secrets=True):
    entry = decrypted_entry_dict(row)
    entry["category"] = normalize_category(entry.get("category"))
    entry["deleted"] = bool(entry.get("deleted"))
    entry["favorite"] = bool(entry.get("favorite"))

    if entry["category"] == "card":
        display_title = clean_text(entry.get("card_name")) or clean_text(entry.get("title")) or "Thẻ ngân hàng"
        display_subtitle = mask_card_number(entry.get("card_number"))
        strength = {"key": "medium", "label": "Bảo mật", "score": 2}
    elif entry["category"] == "note":
        display_title = clean_text(entry.get("note_title")) or clean_text(entry.get("title")) or "Ghi chú bảo mật"
        content = clean_text(entry.get("note_content")) or clean_text(entry.get("notes"))
        display_subtitle = content[:64] + ("..." if len(content) > 64 else "") if content else "Ghi chú trống"
        strength = {"key": "medium", "label": "Ghi chú", "score": 2}
    else:
        display_title = clean_text(entry.get("title")) or clean_text(urlparse(entry.get("url") or "").netloc) or "Đăng nhập"
        display_subtitle = clean_text(entry.get("username")) or clean_text(entry.get("url")) or "Chưa có tài khoản"
        strength = password_strength(entry.get("password") or "")

    entry["display_title"] = display_title
    entry["display_subtitle"] = display_subtitle
    entry["strength"] = strength["key"]
    entry["strength_label"] = strength["label"]
    entry["strength_score"] = strength["score"]
    entry["favicon_letter"] = first_letter(display_title)
    entry["favicon_color"] = favicon_color(display_title)
    if not include_secrets:
        for field in SENSITIVE_FIELDS:
            entry[field] = ""
        if entry["category"] == "note":
            entry["display_subtitle"] = "Nội dung được bảo vệ"
    return entry


def current_user_entries(include_deleted=False):
    deleted_clause = "" if include_deleted else "AND deleted = 0"
    rows = query_db(
        f"SELECT * FROM entries WHERE user_id = ? {deleted_clause} ORDER BY updated_at DESC",
        (g.user["id"],),
    )
    return [display_entry(row, include_secrets=False) for row in rows]


def entry_counts():
    rows = query_db(
        """
        SELECT
            SUM(CASE WHEN deleted = 0 THEN 1 ELSE 0 END) AS all_count,
            SUM(CASE WHEN deleted = 0 AND favorite = 1 THEN 1 ELSE 0 END) AS favorite_count,
            SUM(CASE WHEN deleted = 0 AND category = 'login' THEN 1 ELSE 0 END) AS login_count,
            SUM(CASE WHEN deleted = 0 AND category = 'card' THEN 1 ELSE 0 END) AS card_count,
            SUM(CASE WHEN deleted = 0 AND category = 'note' THEN 1 ELSE 0 END) AS note_count,
            SUM(CASE WHEN deleted = 1 THEN 1 ELSE 0 END) AS trash_count
        FROM entries
        WHERE user_id = ?
        """,
        (g.user["id"],),
        one=True,
    )
    return {
        "all": rows["all_count"] or 0,
        "favorites": rows["favorite_count"] or 0,
        "login": rows["login_count"] or 0,
        "card": rows["card_count"] or 0,
        "note": rows["note_count"] or 0,
        "trash": rows["trash_count"] or 0,
    }


def audit_summary(entries):
    login_entries = [entry for entry in entries if entry["category"] == "login" and not entry["deleted"]]
    weak = [entry for entry in login_entries if entry["strength"] == "weak"]
    medium = [entry for entry in login_entries if entry["strength"] == "medium"]
    strong = [entry for entry in login_entries if entry["strength"] == "strong"]
    reused = {}
    for entry in login_entries:
        password = entry.get("password") or ""
        if password:
            reused.setdefault(password, []).append(entry)
    reused_groups = [group for group in reused.values() if len(group) > 1]
    reused_count = sum(len(group) for group in reused_groups)

    total = len(login_entries)
    penalty = min(70, len(weak) * 18 + len(medium) * 6 + reused_count * 10)
    score = 100 if total == 0 else max(20, 100 - penalty)
    label = "Tốt" if score >= 75 else "Cần chú ý" if score >= 50 else "Rủi ro cao"

    return {
        "score": score,
        "label": label,
        "total": total,
        "weak": len(weak),
        "medium": len(medium),
        "strong": len(strong),
        "reused": reused_count,
        "weak_entries": weak,
        "reused_groups": reused_groups,
    }


def filtered_entries(section):
    if section == "trash":
        rows = query_db(
            "SELECT * FROM entries WHERE user_id = ? AND deleted = 1 ORDER BY deleted_at DESC, updated_at DESC",
            (g.user["id"],),
        )
    elif section == "favorites":
        rows = query_db(
            "SELECT * FROM entries WHERE user_id = ? AND deleted = 0 AND favorite = 1 ORDER BY updated_at DESC",
            (g.user["id"],),
        )
    elif section in ENTRY_CATEGORIES:
        rows = query_db(
            "SELECT * FROM entries WHERE user_id = ? AND deleted = 0 AND category = ? ORDER BY updated_at DESC",
            (g.user["id"], section),
        )
    else:
        rows = query_db(
            "SELECT * FROM entries WHERE user_id = ? AND deleted = 0 ORDER BY updated_at DESC",
            (g.user["id"],),
        )
    return [display_entry(row) for row in rows]


def section_from_request():
    if request.args.get("view") == "trash":
        return "trash"
    category = request.args.get("cat", "all")
    if category == "favorites" or category in ENTRY_CATEGORIES:
        return category
    return "all"


def section_meta(section):
    titles = {
        "all": ("Tất cả mục nhập", "Toàn bộ dữ liệu chưa xóa trong kho của bạn."),
        "favorites": ("Yêu thích", "Các mục bạn đã đánh dấu để truy cập nhanh."),
        "login": ("Đăng nhập", "Tài khoản website, ứng dụng và dịch vụ."),
        "card": ("Thẻ ngân hàng", "Thông tin thẻ được lưu trong kho cá nhân."),
        "note": ("Ghi chú bảo mật", "Ghi chú riêng tư và dữ liệu nhạy cảm."),
        "trash": ("Thùng rác", "Mục đã xóa mềm, có thể khôi phục hoặc xóa vĩnh viễn."),
    }
    return titles.get(section, titles["all"])


def build_entry_payload(data):
    category = normalize_category(data.get("category"))
    now = utc_now()
    payload = {
        "category": category,
        "title": clean_text(data.get("title")),
        "username": clean_text(data.get("username")),
        "url": clean_text(data.get("url")),
        "password": data.get("password") or "",
        "notes": clean_text(data.get("notes")),
        "favorite": 1 if data.get("favorite") in (True, "true", "1", "on", 1) else 0,
        "card_name": clean_text(data.get("card_name")),
        "card_number": clean_text(data.get("card_number")),
        "card_expiry": clean_text(data.get("card_expiry")),
        "card_cvv": clean_text(data.get("card_cvv")),
        "note_title": clean_text(data.get("note_title")),
        "note_content": clean_text(data.get("note_content")),
        "updated_at": now,
    }

    if category == "card":
        payload["title"] = payload["card_name"] or payload["title"] or "Thẻ ngân hàng"
        payload["username"] = ""
        payload["password"] = ""
    elif category == "note":
        payload["title"] = payload["note_title"] or payload["title"] or "Ghi chú bảo mật"
        payload["notes"] = payload["note_content"] or payload["notes"]
    else:
        payload["title"] = payload["title"] or clean_text(urlparse(payload["url"]).netloc) or "Mục đăng nhập"

    return payload


def validate_entry_payload(payload):
    if payload["category"] == "card" and not (payload["card_name"] or payload["card_number"]):
        return "Vui lòng nhập tên chủ thẻ hoặc số thẻ."
    if payload["category"] == "note" and not (payload["note_title"] or payload["note_content"]):
        return "Vui lòng nhập tiêu đề hoặc nội dung ghi chú."
    if payload["category"] == "login" and not (payload["title"] or payload["username"] or payload["url"] or payload["password"]):
        return "Vui lòng nhập ít nhất một thông tin đăng nhập."
    return None


def json_object_or_empty():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def insert_entry(user_id, payload, deleted=0, deleted_at=None, created_at=None):
    stored = encrypted_payload(payload)
    now = utc_now()
    created = created_at or now
    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO entries (
            user_id, title, username, url, password, notes, category, favorite,
            card_name, card_number, card_expiry, card_cvv, note_title, note_content,
            deleted, deleted_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            stored["title"],
            stored["username"],
            stored["url"],
            stored["password"],
            stored["notes"],
            stored["category"],
            stored["favorite"],
            stored["card_name"],
            stored["card_number"],
            stored["card_expiry"],
            stored["card_cvv"],
            stored["note_title"],
            stored["note_content"],
            1 if deleted else 0,
            deleted_at,
            created,
            stored["updated_at"],
        ),
    )
    db.commit()
    return cursor.lastrowid


def exportable_entry(entry):
    fields = [
        "category",
        "title",
        "username",
        "url",
        "password",
        "notes",
        "favorite",
        "card_name",
        "card_number",
        "card_expiry",
        "card_cvv",
        "note_title",
        "note_content",
        "deleted",
        "deleted_at",
        "created_at",
        "updated_at",
    ]
    return {field: entry.get(field) for field in fields}


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        if not email or not password:
            return render_template("login.html", error="Email và mật khẩu không được để trống.", email=email)

        user = query_db("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = remember
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Email hoặc mật khẩu không đúng.", email=email)

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_pw = request.form.get("confirm_password", "")
        agree_terms = request.form.get("agree_terms") == "on"

        context = {"first_name": first_name, "last_name": last_name, "email": email}
        if not first_name or not last_name or not email:
            return render_template("register.html", error="Vui lòng điền đầy đủ thông tin.", **context)
        if not agree_terms:
            return render_template("register.html", error="Bạn phải đồng ý điều khoản dịch vụ.", **context)
        if password != confirm_pw:
            return render_template("register.html", error="Xác nhận mật khẩu không khớp.", **context)
        if len(password) < 12:
            return render_template("register.html", error="Mật khẩu phải có ít nhất 12 ký tự.", **context)
        if query_db("SELECT id FROM users WHERE email = ?", (email,), one=True):
            return render_template("register.html", error="Email này đã được đăng ký.", **context)

        db = get_db()
        db.execute(
            "INSERT INTO users (first_name, last_name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
            (first_name, last_name, email, generate_password_hash(password), utc_now()),
        )
        db.commit()
        flash("Đăng ký thành công! Hãy đăng nhập.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    flash("Tính năng đặt lại mật khẩu sẽ được bổ sung ở phiên bản sau.", "info")
    return redirect(url_for("login"))


@app.route("/terms")
def terms():
    return render_template("legal.html", page_title="Điều khoản dịch vụ", page_kind="terms")


@app.route("/privacy")
def privacy():
    return render_template("legal.html", page_title="Chính sách bảo mật", page_kind="privacy")


@app.route("/dashboard")
@login_required
def dashboard():
    section = section_from_request()
    title, subtitle = section_meta(section)
    entries = filtered_entries(section)
    all_entries = current_user_entries()
    return render_template(
        "dashboard.html",
        entries=entries,
        counts=entry_counts(),
        audit=audit_summary(all_entries),
        active_section=section,
        section_title=title,
        section_subtitle=subtitle,
        show_deleted=section == "trash",
    )


@app.route("/generator")
@login_required
def generator():
    return render_template("generator.html", counts=entry_counts(), active_section="generator")


@app.route("/audit")
@login_required
def audit():
    entries = current_user_entries()
    return render_template(
        "audit.html",
        counts=entry_counts(),
        active_section="audit",
        audit=audit_summary(entries),
        entries=entries,
    )


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        action = request.form.get("action")
        db = get_db()
        if action == "profile":
            first_name = request.form.get("first_name", "").strip()
            last_name = request.form.get("last_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            if not first_name or not last_name or not email:
                flash("Vui lòng nhập đủ họ, tên và email.", "error")
            else:
                existing = query_db("SELECT id FROM users WHERE email = ? AND id != ?", (email, g.user["id"]), one=True)
                if existing:
                    flash("Email này đang được tài khoản khác sử dụng.", "error")
                else:
                    db.execute(
                        "UPDATE users SET first_name = ?, last_name = ?, email = ? WHERE id = ?",
                        (first_name, last_name, email, g.user["id"]),
                    )
                    db.commit()
                    flash("Đã cập nhật hồ sơ.", "success")
        elif action == "password":
            current = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            user = query_db("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],), one=True)
            if not user or not check_password_hash(user["password_hash"], current):
                flash("Mật khẩu hiện tại không đúng.", "error")
            elif len(new_password) < 12:
                flash("Mật khẩu mới phải có ít nhất 12 ký tự.", "error")
            elif new_password != confirm:
                flash("Xác nhận mật khẩu mới không khớp.", "error")
            else:
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(new_password), g.user["id"]),
                )
                db.commit()
                flash("Đã đổi mật khẩu.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", counts=entry_counts(), active_section="settings")


@app.route("/api/export", methods=["GET"])
@login_required
def api_export():
    entries = [exportable_entry(entry) for entry in current_user_entries(include_deleted=True)]
    payload = {
        "app": "VaultX",
        "version": 1,
        "exported_at": utc_now(),
        "account": {"email": g.user["email"], "name": g.user["name"]},
        "entries": entries,
    }
    filename = f"vaultx-export-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api/import", methods=["POST"])
@login_required
def api_import():
    uploaded = request.files.get("import_file")
    if not uploaded or not uploaded.filename:
        flash("Vui lòng chọn file JSON để import.", "error")
        return redirect(url_for("settings"))

    try:
        data = json.loads(uploaded.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        flash("File import không phải JSON hợp lệ.", "error")
        return redirect(url_for("settings"))

    entries = data.get("entries") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        flash("File import không có danh sách mục nhập.", "error")
        return redirect(url_for("settings"))

    imported = 0
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            continue
        payload = build_entry_payload(raw_entry)
        if validate_entry_payload(payload):
            continue
        insert_entry(
            g.user["id"],
            payload,
            deleted=1 if raw_entry.get("deleted") else 0,
            deleted_at=raw_entry.get("deleted_at"),
            created_at=raw_entry.get("created_at"),
        )
        imported += 1

    flash(f"Đã import {imported} mục nhập.", "success" if imported else "warning")
    return redirect(url_for("dashboard"))


@app.route("/api/entries", methods=["GET"])
@login_required
def api_get_entries():
    section = request.args.get("section") or section_from_request()
    entries = filtered_entries(section)
    return jsonify({"entries": entries, "total": len(entries), "counts": entry_counts()})


@app.route("/api/entries", methods=["POST"])
@login_required
def api_create_entry():
    data = json_object_or_empty()
    payload = build_entry_payload(data)
    error = validate_entry_payload(payload)
    if error:
        return jsonify({"error": error}), 400

    entry_id = insert_entry(g.user["id"], payload)
    entry = query_db("SELECT * FROM entries WHERE id = ? AND user_id = ?", (entry_id, g.user["id"]), one=True)
    return jsonify({"entry": display_entry(entry), "message": "Đã tạo mục mới."}), 201


@app.route("/api/entries/<int:entry_id>", methods=["GET"])
@login_required
def api_get_entry(entry_id):
    entry = query_db("SELECT * FROM entries WHERE id = ? AND user_id = ?", (entry_id, g.user["id"]), one=True)
    if not entry:
        return jsonify({"error": "Không tìm thấy mục nhập."}), 404
    return jsonify(display_entry(entry))


@app.route("/api/entries/<int:entry_id>", methods=["PUT"])
@login_required
def api_update_entry(entry_id):
    data = json_object_or_empty()
    existing = query_db("SELECT * FROM entries WHERE id = ? AND user_id = ?", (entry_id, g.user["id"]), one=True)
    if not existing:
        return jsonify({"error": "Không tìm thấy mục nhập."}), 404

    payload = build_entry_payload(data)
    if "favorite" not in data:
        payload["favorite"] = existing["favorite"] or 0
    error = validate_entry_payload(payload)
    if error:
        return jsonify({"error": error}), 400

    stored = encrypted_payload(payload)
    db = get_db()
    db.execute(
        """
        UPDATE entries
        SET title = ?, username = ?, url = ?, password = ?, notes = ?, category = ?, favorite = ?,
            card_name = ?, card_number = ?, card_expiry = ?, card_cvv = ?,
            note_title = ?, note_content = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
        """,
        (
            stored["title"],
            stored["username"],
            stored["url"],
            stored["password"],
            stored["notes"],
            stored["category"],
            stored["favorite"],
            stored["card_name"],
            stored["card_number"],
            stored["card_expiry"],
            stored["card_cvv"],
            stored["note_title"],
            stored["note_content"],
            stored["updated_at"],
            entry_id,
            g.user["id"],
        ),
    )
    db.commit()
    updated = query_db("SELECT * FROM entries WHERE id = ? AND user_id = ?", (entry_id, g.user["id"]), one=True)
    return jsonify({"entry": display_entry(updated), "message": "Đã cập nhật mục nhập."})


@app.route("/api/entries/<int:entry_id>", methods=["DELETE"])
@login_required
def api_delete_entry(entry_id):
    entry = query_db("SELECT * FROM entries WHERE id = ? AND user_id = ?", (entry_id, g.user["id"]), one=True)
    if not entry:
        return jsonify({"error": "Không tìm thấy mục nhập."}), 404

    db = get_db()
    if entry["deleted"]:
        db.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (entry_id, g.user["id"]))
        db.commit()
        return jsonify({"message": "Đã xóa vĩnh viễn."})

    db.execute(
        "UPDATE entries SET deleted = 1, deleted_at = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (utc_now(), utc_now(), entry_id, g.user["id"]),
    )
    db.commit()
    return jsonify({"message": "Đã chuyển vào thùng rác."})


@app.route("/api/entries/<int:entry_id>/restore", methods=["POST"])
@login_required
def api_restore_entry(entry_id):
    entry = query_db(
        "SELECT * FROM entries WHERE id = ? AND user_id = ? AND deleted = 1",
        (entry_id, g.user["id"]),
        one=True,
    )
    if not entry:
        return jsonify({"error": "Không tìm thấy mục nhập trong thùng rác."}), 404

    db = get_db()
    db.execute(
        "UPDATE entries SET deleted = 0, deleted_at = NULL, updated_at = ? WHERE id = ? AND user_id = ?",
        (utc_now(), entry_id, g.user["id"]),
    )
    db.commit()
    return jsonify({"message": "Đã khôi phục mục nhập."})


@app.route("/api/entries/<int:entry_id>/favorite", methods=["POST"])
@login_required
def api_toggle_favorite(entry_id):
    entry = query_db(
        "SELECT id, favorite FROM entries WHERE id = ? AND user_id = ? AND deleted = 0",
        (entry_id, g.user["id"]),
        one=True,
    )
    if not entry:
        return jsonify({"error": "Không tìm thấy mục nhập."}), 404

    favorite = 0 if entry["favorite"] else 1
    db = get_db()
    db.execute(
        "UPDATE entries SET favorite = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (favorite, utc_now(), entry_id, g.user["id"]),
    )
    db.commit()
    return jsonify({"favorite": bool(favorite), "message": "Đã cập nhật yêu thích."})


@app.route("/api/entries/<int:entry_id>/copy", methods=["POST"])
@login_required
def api_copy_password(entry_id):
    entry = query_db(
        "SELECT * FROM entries WHERE id = ? AND user_id = ? AND deleted = 0",
        (entry_id, g.user["id"]),
        one=True,
    )
    if not entry:
        return jsonify({"error": "Không tìm thấy mục nhập."}), 404

    entry = decrypted_entry_dict(entry)
    category = normalize_category(entry["category"])
    if category == "card":
        value = entry["card_number"] or entry["password"] or ""
    elif category == "note":
        value = entry["note_content"] or entry["notes"] or ""
    else:
        value = entry["password"] or ""
    return jsonify({"value": value, "password": value})


@app.route("/api/generate-password", methods=["POST"])
@login_required
def api_generate_password():
    data = json_object_or_empty()
    try:
        length = min(max(int(data.get("length", 16)), 8), 64)
    except (TypeError, ValueError):
        return jsonify({"error": "Độ dài mật khẩu không hợp lệ."}), 400

    classes = []
    if data.get("upper", True):
        classes.append(string.ascii_uppercase)
    if data.get("lower", True):
        classes.append(string.ascii_lowercase)
    if data.get("digits", True):
        classes.append(string.digits)
    if data.get("symbols", True):
        classes.append("!@#$%^&*()-_=+[]{}|;:,.<>?")
    if not classes:
        classes = [string.ascii_letters + string.digits]

    length = max(length, len(classes))
    alphabet = "".join(classes)
    characters = [secrets.choice(char_class) for char_class in classes]
    characters.extend(secrets.choice(alphabet) for _ in range(length - len(characters)))
    secrets.SystemRandom().shuffle(characters)
    password = "".join(characters)
    return jsonify({"password": password, "strength": password_strength(password)})


if __name__ == "__main__":
    app.run(
        debug=False,
        host=os.environ.get("VAULTX_HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
    )
