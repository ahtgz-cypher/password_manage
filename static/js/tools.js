/* tools.js - generator and small utility page interactions */

'use strict';

const sidebarToggle = document.getElementById('sidebarToggle');
const sidebar = document.querySelector('.sidebar');
sidebarToggle?.addEventListener('click', () => sidebar?.classList.toggle('open'));

const lengthRange = document.getElementById('lengthRange');
const lengthValue = document.getElementById('lengthValue');
const generatedPassword = document.getElementById('generatedPassword');
const generateMainBtn = document.getElementById('generateMainBtn');
const copyGeneratedBtn = document.getElementById('copyGeneratedBtn');
const saveGeneratedForm = document.getElementById('saveGeneratedForm');
const generatorError = document.getElementById('generatorError');

lengthRange?.addEventListener('input', () => {
  if (lengthValue) lengthValue.textContent = lengthRange.value;
});

function generatorOptions() {
  return {
    length: Number(lengthRange?.value || 18),
    upper: document.getElementById('optUpper')?.checked ?? true,
    lower: document.getElementById('optLower')?.checked ?? true,
    digits: document.getElementById('optDigits')?.checked ?? true,
    symbols: document.getElementById('optSymbols')?.checked ?? true,
  };
}

async function generateFromServer() {
  setButtonLoading(generateMainBtn, true);
  if (generatorError) generatorError.textContent = '';
  try {
    const res = await fetchWithCsrf('/api/generate-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(generatorOptions()),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Không tạo được mật khẩu.');
    generatedPassword.value = data.password;
    checkPasswordStrength(data.password, 'generatorStrengthMeter', 'generatorStrengthFill', 'generatorStrengthLabel');
    return data.password;
  } catch (error) {
    if (generatorError) generatorError.textContent = error.message || 'Tạo mật khẩu thất bại.';
    return '';
  } finally {
    setButtonLoading(generateMainBtn, false);
  }
}

generateMainBtn?.addEventListener('click', generateFromServer);

copyGeneratedBtn?.addEventListener('click', async () => {
  const password = generatedPassword?.value || await generateFromServer();
  if (!password) return;
  const copied = await copyToClipboard(password, copyGeneratedBtn);
  if (generatorError) generatorError.textContent = copied ? '' : 'Không thể truy cập clipboard.';
});

saveGeneratedForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (generatorError) generatorError.textContent = '';

  const password = generatedPassword?.value || await generateFromServer();
  const title = document.getElementById('saveTitle')?.value.trim() || 'Mật khẩu mới';
  const username = document.getElementById('saveUsername')?.value.trim() || '';
  if (!password) return;

  const btn = document.getElementById('saveGeneratedBtn');
  setButtonLoading(btn, true);
  try {
    const res = await fetchWithCsrf('/api/entries', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ category: 'login', title, username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Không lưu được mật khẩu.');
    window.location.href = `/dashboard?cat=login&edit=${data.entry.id}`;
  } catch (error) {
    if (generatorError) generatorError.textContent = error.message || 'Lưu thất bại.';
  } finally {
    setButtonLoading(btn, false);
  }
});

if (generateMainBtn) {
  generateFromServer();
}
