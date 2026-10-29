/* =========================================
   base.js — Global utilities
   VaultX Password Manager
   ========================================= */

'use strict';

async function fetchWithCsrf(url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const token = document.querySelector('meta[name="csrf-token"]')?.content;
    if (token) headers.set('X-CSRFToken', token);
  }
  return fetch(url, { ...options, headers });
}

/**
 * Toggle password field visibility.
 * @param {string} fieldId - The input element ID
 */
function togglePassword(fieldId) {
  const input = document.getElementById(fieldId);
  if (!input) return;
  const wrap = input.closest('.field-wrap');
  const eyeShow = wrap?.querySelector('.eye-show');
  const eyeHide = wrap?.querySelector('.eye-hide');

  if (input.type === 'password') {
    input.type = 'text';
    if (eyeShow) eyeShow.style.display = 'none';
    if (eyeHide) eyeHide.style.display = '';
  } else {
    input.type = 'password';
    if (eyeShow) eyeShow.style.display = '';
    if (eyeHide) eyeHide.style.display = 'none';
  }
}

/**
 * Evaluate password strength.
 * Returns { score: 0-5, label, color }
 */
function evaluatePassword(password) {
  if (!password) return { score: 0, label: '', color: '' };

  let score = 0;
  if (password.length >= 8)  score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;

  const levels = [
    { label: 'Yếu',        color: '#f87171' },
    { label: 'Yếu',        color: '#fb923c' },
    { label: 'Trung bình', color: '#f59e0b' },
    { label: 'Trung bình', color: '#f59e0b' },
    { label: 'Mạnh',       color: '#22d3a5' },
    { label: 'Mạnh',       color: '#22d3a5' },
  ];
  const idx = Math.min(score, levels.length - 1);
  return { score, ...levels[idx] };
}

/**
 * Update strength meter UI.
 * @param {string} password
 * @param {string} meterId   - container id (strength-meter div)
 * @param {string} fillId    - fill bar id
 * @param {string} labelId   - label span id
 */
function checkPasswordStrength(password, meterId = 'strengthMeter', fillId = 'strengthFill', labelId = 'strengthLabel') {
  const meter = document.getElementById(meterId);
  const fill  = document.getElementById(fillId);
  const lbl   = document.getElementById(labelId);
  if (!meter || !fill || !lbl) return;

  if (!password) {
    meter.style.display = 'none';
    return;
  }

  meter.style.display = 'flex';
  const result = evaluatePassword(password);
  const pct = (result.score / 5) * 100;
  fill.style.width = pct + '%';
  fill.style.background = result.color;
  lbl.textContent = result.label;
  lbl.style.color = result.color;
}

/**
 * Generate a secure random password.
 * @param {number} length
 * @param {object} options
 */
function generatePassword(length = 16, options = {}) {
  const { upper = true, lower = true, digits = true, symbols = true } = options;
  const groups = [];
  if (upper) groups.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if (lower) groups.push('abcdefghijklmnopqrstuvwxyz');
  if (digits) groups.push('0123456789');
  if (symbols) groups.push('!@#$%^&*()-_=+[]{}|;:,.<>?');
  if (!groups.length) return '';

  const safeLength = Math.max(8, Math.min(Number(length) || 16, 64), groups.length);
  const alphabet = groups.join('');
  const chars = groups.map((group) => group[randomIndex(group.length)]);
  while (chars.length < safeLength) chars.push(alphabet[randomIndex(alphabet.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

function randomIndex(limit) {
  const range = 0x100000000;
  const cutoff = range - (range % limit);
  const value = new Uint32Array(1);
  do { crypto.getRandomValues(value); } while (value[0] >= cutoff);
  return value[0] % limit;
}

/**
 * Copy text to clipboard with visual feedback.
 * @param {string} text
 * @param {HTMLElement} btn - button to show feedback on
 */
async function copyToClipboard(text, btn = null) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const temp = document.createElement('textarea');
      temp.value = text;
      temp.setAttribute('readonly', '');
      temp.style.position = 'fixed';
      temp.style.opacity = '0';
      document.body.appendChild(temp);
      temp.select();
      document.execCommand('copy');
      temp.remove();
    }
    if (btn) {
      const original = btn.innerHTML;
      btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 14 14"><path d="M2 7l3.5 3.5L12 3" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>';
      btn.style.color = 'var(--success)';
      setTimeout(() => {
        btn.innerHTML = original;
        btn.style.color = '';
      }, 1800);
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Show/hide loading state on a button.
 */
function setButtonLoading(btn, loading) {
  const text = btn.querySelector('.btn-text');
  const loader = btn.querySelector('.btn-loader');
  if (!text || !loader) return;
  text.style.display = loading ? 'none' : '';
  loader.style.display = loading ? 'inline-block' : 'none';
  btn.disabled = loading;
}

// Keyboard shortcut: Cmd/Ctrl+K → focus search
document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
    e.preventDefault();
    const search = document.getElementById('searchInput');
    if (search) search.focus();
  }
});
