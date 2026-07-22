window.CS = window.CS || {};

CS.Auth = (() => {
  const storageKey = 'cs_auth_user';

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(storageKey) || 'null');
    } catch {
      return null;
    }
  }

  async function apiFetch(path, options = {}) {
    const base = window.CS_API_BASE || '';
    const url = path.startsWith('http') ? path : `${base}${path}`;
    const response = await fetch(url, options);
    const json = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(json?.error?.message || json?.error || `HTTP ${response.status}`);
    }

    return json;
  }

  function showLoginModal() {
    const user = { id: 'local-preview', plan: 'preview' };
    localStorage.setItem(storageKey, JSON.stringify(user));
    document.dispatchEvent(new CustomEvent('cs:login', { detail: user }));
  }

  function init() {
    const user = getUser();
    document.dispatchEvent(new CustomEvent(user ? 'cs:login' : 'cs:guest', { detail: user }));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    queueMicrotask(init);
  }

  return {
    apiFetch,
    showLoginModal,
    getUser
  };
})();
