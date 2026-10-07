const key = 'cyberintel.session';
export const demoEnabled = import.meta.env.DEV && import.meta.env.VITE_ENABLE_DEMO === 'true';
export function readSession() {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) || localStorage.getItem(key) || 'null');
    if (!value || !Number.isFinite(value.expiresAt) || value.expiresAt <= Date.now() || !value.user?.name || !value.token || (value.demo && !demoEnabled)) return null;
    return value;
  } catch { return null; }
}
export function clearSession() { localStorage.removeItem(key); sessionStorage.removeItem(key); }
export function saveSession(data, remember) {
  clearSession();
  const expiresAt = data.demo ? Date.now() + 3600000 : JSON.parse(atob(data.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).exp * 1000;
  const session = { ...data, expiresAt };
  (remember ? localStorage : sessionStorage).setItem(key, JSON.stringify(session));
  return session;
}
