/* =========================================
   auth.js — Login & Register interactions
   VaultX Password Manager
   ========================================= */

'use strict';

/* ---- Login form ---- */
const loginForm = document.getElementById('loginForm');
if (loginForm) {
  loginForm.addEventListener('submit', (e) => {
    let valid = true;

    const email    = document.getElementById('email');
    const password = document.getElementById('password');
    const emailErr = document.getElementById('emailError');
    const pwErr    = document.getElementById('passwordError');

    // Clear previous errors
    [emailErr, pwErr].forEach(el => { if (el) el.textContent = ''; });
    [email, password].forEach(el => el?.classList.remove('error'));

    if (!email.value.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim())) {
      emailErr.textContent = 'Vui lòng nhập email hợp lệ.';
      email.classList.add('error');
      valid = false;
    }

    if (!password.value) {
      pwErr.textContent = 'Vui lòng nhập mật khẩu chủ.';
      password.classList.add('error');
      valid = false;
    }

    if (!valid) {
      e.preventDefault();
      return;
    }

    // Show loading state
    const btn = document.getElementById('loginBtn');
    if (btn) setButtonLoading(btn, true);
    // Form submits normally to backend
  });
}

/* ---- Register form ---- */
const registerForm = document.getElementById('registerForm');
if (registerForm) {
  registerForm.addEventListener('submit', (e) => {
    let valid = true;

    const email   = document.getElementById('email');
    const pw      = document.getElementById('password');
    const confirm = document.getElementById('confirm_password');
    const terms   = document.getElementById('agree_terms');
    const emailErr   = document.getElementById('emailError');
    const pwErr      = document.getElementById('passwordError');
    const confirmErr = document.getElementById('confirmError');

    [emailErr, pwErr, confirmErr].forEach(el => { if (el) el.textContent = ''; });
    registerForm.querySelector('.terms-error')?.remove();
    [email, pw, confirm].forEach(el => el?.classList.remove('error'));

    if (!email.value.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim())) {
      emailErr.textContent = 'Email không hợp lệ.';
      email.classList.add('error');
      valid = false;
    }

    if (pw.value.length < 12) {
      pwErr.textContent = 'Mật khẩu chủ phải có ít nhất 12 ký tự.';
      pw.classList.add('error');
      valid = false;
    }

    if (confirm.value !== pw.value) {
      confirmErr.textContent = 'Xác nhận mật khẩu không khớp.';
      confirm.classList.add('error');
      valid = false;
    }

    if (!terms.checked) {
      valid = false;
      const msg = document.createElement('p');
      msg.style.cssText = 'color:var(--danger);font-size:.78rem;margin-top:-8px;';
      msg.textContent = 'Bạn cần đồng ý với điều khoản dịch vụ.';
      const existing = registerForm.querySelector('.terms-error');
      if (!existing) {
        msg.className = 'terms-error';
        terms.closest('.field-checkbox').appendChild(msg);
      }
    }

    if (!valid) {
      e.preventDefault();
      return;
    }

    const btn = document.getElementById('registerBtn');
    if (btn) setButtonLoading(btn, true);
  });
}

/* ---- Inline strength check for register page entry ---- */
// Wires up the strength meter for the confirm field in the entry modal as well
document.addEventListener('DOMContentLoaded', () => {
  const entryPw = document.getElementById('entryPassword');
  if (entryPw) {
    entryPw.addEventListener('input', () => {
      checkPasswordStrength(
        entryPw.value,
        'entryStrengthMeter',
        'entryStrengthFill',
        'entryStrengthLabel'
      );
    });
  }
});
