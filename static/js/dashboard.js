/* dashboard.js - Dashboard interactions for VaultX */

'use strict';

const appState = window.VaultX || {};

const sidebarToggle = document.getElementById('sidebarToggle');
const sidebar = document.querySelector('.sidebar');
const modal = document.getElementById('entryModal');
const addBtn = document.getElementById('addEntryBtn');
const emptyAddBtn = document.getElementById('emptyAddBtn');
const closeBtn = document.getElementById('closeModal');
const cancelBtn = document.getElementById('cancelModal');
const entryForm = document.getElementById('entryForm');
const modalTitle = document.getElementById('modalTitle');
const entriesGrid = document.getElementById('entriesGrid');
const entryCategory = document.getElementById('entryCategory');
const entryFormError = document.getElementById('entryFormError');
const entryPassword = document.getElementById('entryPassword');
const entryFavorite = document.getElementById('entryFavorite');

if (sidebarToggle && sidebar) {
  sidebarToggle.addEventListener('click', () => sidebar.classList.toggle('open'));
  document.addEventListener('click', (event) => {
    if (!sidebar.contains(event.target) && !sidebarToggle.contains(event.target)) {
      sidebar.classList.remove('open');
    }
  });
}

function preferredCategory() {
  return ['login', 'card', 'note'].includes(appState.activeSection) ? appState.activeSection : 'login';
}

function setCategory(category) {
  const nextCategory = ['login', 'card', 'note'].includes(category) ? category : 'login';
  if (entryCategory) entryCategory.value = nextCategory;

  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === nextCategory);
  });
  document.querySelectorAll('.tab-pane').forEach((pane) => {
    pane.classList.toggle('active', pane.id === `tab-${nextCategory}`);
  });
}

function clearModalErrors() {
  if (entryFormError) entryFormError.textContent = '';
  entryForm?.querySelectorAll('.error').forEach((input) => input.classList.remove('error'));
}

function resetModalForm(category = preferredCategory()) {
  if (!entryForm) return;
  entryForm.reset();
  document.getElementById('entryId').value = '';
  if (entryFavorite) entryFavorite.checked = appState.activeSection === 'favorites';
  setCategory(category);
  clearModalErrors();

  const meter = document.getElementById('entryStrengthMeter');
  if (meter) meter.style.display = 'none';
  if (entryPassword) entryPassword.type = 'password';
}

function openModal(title = 'Thêm mục mới', data = null, category = preferredCategory()) {
  if (!modal) return;
  modalTitle.textContent = title;
  resetModalForm(category);
  if (data) populateModalForm(data);
  modal.classList.add('active');
  modal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  if (!modal) return;
  modal.classList.remove('active');
  modal.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
  resetModalForm();
}

function populateModalForm(data) {
  if (!entryForm) return;
  document.getElementById('entryId').value = data.id || '';
  setCategory(data.category || 'login');

  Object.entries(data).forEach(([key, value]) => {
    const field = entryForm.elements[key];
    if (!field || field.type === 'checkbox') return;
    field.value = value ?? '';
  });

  if (entryFavorite) entryFavorite.checked = Boolean(data.favorite);
  if (entryPassword) {
    entryPassword.type = 'password';
    checkPasswordStrength(entryPassword.value, 'entryStrengthMeter', 'entryStrengthFill', 'entryStrengthLabel');
  }
}

async function openExistingEntry(entryId) {
  try {
    const res = await fetch(`/api/entries/${entryId}`);
    if (!res.ok) throw new Error('Không tải được mục nhập');
    const data = await res.json();
    openModal('Chỉnh sửa mục', data, data.category);
  } catch (error) {
    showToast(error.message || 'Không mở được mục nhập.', 'error');
  }
}

function buildPayload() {
  const formData = new FormData(entryForm);
  const payload = Object.fromEntries(formData.entries());
  payload.category = entryCategory?.value || 'login';
  payload.favorite = Boolean(entryFavorite?.checked);
  return payload;
}

function validatePayload(payload) {
  const fields = [];
  if (payload.category === 'card') {
    fields.push(['card_name', 'card_number']);
  } else if (payload.category === 'note') {
    fields.push(['note_title', 'note_content']);
  } else {
    fields.push(['title', 'username', 'url', 'password']);
  }

  const valid = fields[0].some((field) => (payload[field] || '').trim());
  if (!valid) {
    return payload.category === 'card'
      ? 'Nhập tên chủ thẻ hoặc số thẻ.'
      : payload.category === 'note'
        ? 'Nhập tiêu đề hoặc nội dung ghi chú.'
        : 'Nhập ít nhất một thông tin đăng nhập.';
  }
  return '';
}

document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => setCategory(btn.dataset.tab));
});

addBtn?.addEventListener('click', () => openModal('Thêm mục mới'));
emptyAddBtn?.addEventListener('click', () => openModal('Thêm mục mới'));
closeBtn?.addEventListener('click', closeModal);
cancelBtn?.addEventListener('click', closeModal);

modal?.addEventListener('click', (event) => {
  if (event.target === modal) closeModal();
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') closeModal();
});

entryPassword?.addEventListener('input', () => {
  checkPasswordStrength(entryPassword.value, 'entryStrengthMeter', 'entryStrengthFill', 'entryStrengthLabel');
});

const generatePwBtn = document.getElementById('generatePwBtn');
generatePwBtn?.addEventListener('click', () => {
  const password = generatePassword(18);
  if (entryPassword) {
    entryPassword.value = password;
    entryPassword.type = 'text';
    checkPasswordStrength(password, 'entryStrengthMeter', 'entryStrengthFill', 'entryStrengthLabel');
  }
});

entryForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearModalErrors();

  const payload = buildPayload();
  const validationError = validatePayload(payload);
  if (validationError) {
    entryFormError.textContent = validationError;
    return;
  }

  const btn = document.getElementById('saveEntryBtn');
  setButtonLoading(btn, true);

  try {
    const url = payload.id ? `/api/entries/${payload.id}` : '/api/entries';
    const method = payload.id ? 'PUT' : 'POST';
    const res = await fetchWithCsrf(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Không lưu được mục nhập');
    showToast(data.message || 'Đã lưu mục nhập.', 'success');
    closeModal();
    setTimeout(() => window.location.reload(), 450);
  } catch (error) {
    entryFormError.textContent = error.message || 'Lưu thất bại.';
  } finally {
    setButtonLoading(btn, false);
  }
});

entriesGrid?.addEventListener('click', async (event) => {
  const card = event.target.closest('.entry-card');
  if (!card) return;
  const entryId = card.dataset.id;

  if (event.target.closest('.card-copy')) {
    event.stopPropagation();
    try {
      const res = await fetchWithCsrf(`/api/entries/${entryId}/copy`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Không sao chép được');
      const copied = await copyToClipboard(data.value || data.password || '', event.target.closest('.card-copy'));
      showToast(copied ? 'Đã sao chép vào clipboard.' : 'Không thể truy cập clipboard.', copied ? 'success' : 'error');
    } catch (error) {
      showToast(error.message || 'Sao chép thất bại.', 'error');
    }
    return;
  }

  if (event.target.closest('.favorite-btn')) {
    event.stopPropagation();
    try {
      const btn = event.target.closest('.favorite-btn');
      const res = await fetchWithCsrf(`/api/entries/${entryId}/favorite`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Không cập nhật được yêu thích');
      btn.classList.toggle('active', data.favorite);
      showToast(data.favorite ? 'Đã thêm vào yêu thích.' : 'Đã bỏ yêu thích.', 'success');
      if (appState.activeSection === 'favorites' && !data.favorite) {
        card.remove();
        updateEntryCount();
      }
    } catch (error) {
      showToast(error.message || 'Cập nhật yêu thích thất bại.', 'error');
    }
    return;
  }

  if (event.target.closest('.restore-btn')) {
    event.stopPropagation();
    if (!confirm('Khôi phục mục nhập này?')) return;
    try {
      const res = await fetchWithCsrf(`/api/entries/${entryId}/restore`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Không khôi phục được');
      card.remove();
      updateEntryCount();
      showToast(data.message || 'Đã khôi phục.', 'success');
    } catch (error) {
      showToast(error.message || 'Khôi phục thất bại.', 'error');
    }
    return;
  }

  if (event.target.closest('.delete-btn')) {
    event.stopPropagation();
    const permanent = appState.showDeleted;
    if (!confirm(permanent ? 'Xóa vĩnh viễn mục này?' : 'Chuyển mục này vào thùng rác?')) return;
    try {
      const res = await fetchWithCsrf(`/api/entries/${entryId}`, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Không xóa được');
      card.remove();
      updateEntryCount();
      showToast(data.message || 'Đã xóa.', 'success');
    } catch (error) {
      showToast(error.message || 'Xóa thất bại.', 'error');
    }
    return;
  }

  openExistingEntry(entryId);
});

function updateEntryCount() {
  const countEl = document.getElementById('entryCount');
  if (!countEl || !entriesGrid) return;
  const count = entriesGrid.querySelectorAll('.entry-card').length;
  countEl.textContent = count;
  if (count === 0 && !document.getElementById('emptyState')) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.id = 'emptyState';
    empty.innerHTML = '<h3>Không còn mục nào</h3><p>Danh sách hiện tại đã trống.</p>';
    entriesGrid.appendChild(empty);
  }
}

const searchInput = document.getElementById('searchInput');
searchInput?.addEventListener('input', debounce((event) => {
  const query = event.target.value.toLowerCase().trim();
  document.querySelectorAll('.entry-card').forEach((card) => {
    const haystack = `${card.dataset.title || ''} ${card.dataset.subtitle || ''}`.toLowerCase();
    card.style.display = !query || haystack.includes(query) ? '' : 'none';
  });
}, 150));

const sortBtn = document.getElementById('sortBtn');
const sortModes = [
  { key: 'newest', label: 'Mới nhất' },
  { key: 'name', label: 'Tên A-Z' },
  { key: 'category', label: 'Danh mục' },
];

sortBtn?.addEventListener('click', () => {
  const currentIndex = sortModes.findIndex((mode) => mode.key === sortBtn.dataset.sort);
  const next = sortModes[(currentIndex + 1) % sortModes.length];
  sortBtn.dataset.sort = next.key;
  sortBtn.lastChild.textContent = ` ${next.label}`;
  sortCards(next.key);
});

function sortCards(mode) {
  if (!entriesGrid) return;
  const cards = Array.from(entriesGrid.querySelectorAll('.entry-card'));
  cards.sort((a, b) => {
    if (mode === 'name') return (a.dataset.title || '').localeCompare(b.dataset.title || '');
    if (mode === 'category') return (a.dataset.category || '').localeCompare(b.dataset.category || '');
    return (b.dataset.updated || '').localeCompare(a.dataset.updated || '');
  });
  cards.forEach((card) => entriesGrid.appendChild(card));
}

const gridViewBtn = document.getElementById('gridViewBtn');
const listViewBtn = document.getElementById('listViewBtn');

gridViewBtn?.addEventListener('click', () => {
  gridViewBtn.classList.add('active');
  listViewBtn?.classList.remove('active');
  entriesGrid?.classList.remove('list-view');
});

listViewBtn?.addEventListener('click', () => {
  listViewBtn.classList.add('active');
  gridViewBtn?.classList.remove('active');
  entriesGrid?.classList.add('list-view');
});

document.getElementById('notificationsBtn')?.addEventListener('click', () => {
  showToast(appState.auditMessage || 'Kho của bạn đang ổn.', 'info');
});

if (appState.editId) {
  openExistingEntry(appState.editId);
}

function showToast(message, type = 'info') {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;';
    document.body.appendChild(container);
  }

  const colors = { success: 'var(--success)', error: 'var(--danger)', info: 'var(--accent)' };
  const toast = document.createElement('div');
  toast.style.cssText = `
    padding: 10px 16px; background: var(--bg-raised);
    border: 1px solid ${colors[type] || colors.info};
    border-radius: var(--radius-md); color: var(--text-primary);
    font-size: .875rem; box-shadow: var(--shadow-md);
  `;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}
