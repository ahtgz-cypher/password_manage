# VaultX Password Manager

VaultX is a local coursework application for storing login records, payment cards, and secure notes. It uses Flask, SQLite, browser templates, and JSON endpoints.

> **Coursework/demo only.** This project is not an independently audited password manager. Do not store real passwords, payment card data, or other production secrets in it.

## Requirements

- Python 3.10 or newer
- Packages listed in `requirements.txt`

## Run locally

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. The app listens on localhost by default and runs with Flask debug mode disabled. Set `PORT` to change the port. Set `VAULTX_HOST` only when you intentionally need a different bind address.

The first run creates two local key files beside `app.py`:

- `.flask_secret.key` signs Flask session cookies.
- `.vaultx.key` encrypts selected vault fields in SQLite.

Keep both keys private and back them up separately from `vault.db`. Losing `.vaultx.key` makes encrypted vault fields unrecoverable. Losing `.flask_secret.key` signs users out but does not affect vault decryption. You can provide `FLASK_SECRET_KEY` and `VAULTX_ENCRYPTION_KEY` as environment variables instead; use strong values and do not commit them.

For HTTPS deployments behind a correctly configured TLS proxy, set `COOKIE_SECURE=1`. The application has no production deployment configuration, account recovery email service, rate limiting, or independent security audit.

## Features

- Registration, login, session logout, profile editing, and password changes
- Login, card, and secure-note records with favorites and a recoverable trash area
- Password generation and a local strength/reuse audit
- JSON import and export
- Per-user record ownership checks on record APIs
- CSRF tokens for form and JSON mutations
- Fernet encryption at rest for usernames, passwords, notes, card numbers, card expiry, card CVV, and secure-note content
- Werkzeug password hashing for account passwords

The strength score is a simple educational heuristic; it is not a security guarantee. Exported JSON is intentionally decrypted and must be handled like a secret.

## Data and migration

SQLite data is stored in `vault.db`. The app creates the schema and migrates older records on startup. The migration encrypts fields that older versions stored in plaintext and clears the duplicate card number previously copied into the `username` column for card records. Back up `vault.db` and `.vaultx.key` before upgrading an existing installation.

The encryption key is stored separately from the database, but the default local files still live in the same project folder. This protects a copied database without its key; it does not protect secrets from someone who can read both files or access a running app account.

## Project structure

```text
app.py
templates/       Jinja pages and reusable components
static/css/      Stylesheets
static/js/       Browser interactions
requirements.txt Python dependencies
BAO_CAO_DACS3_hoan_thien.docx  Project report
vault.db         Local application data (created/used at runtime)
```

## Security scope

Use this project for coursework demonstrations with dummy data. A production password manager would need a security design review, stronger key management (for example, a user-derived vault key), secure deployment and HTTPS, abuse controls, recovery and backup procedures, and independent testing. Never expose Flask's development server to the public internet.
