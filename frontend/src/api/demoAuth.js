import { demoEnabled } from '../utils/session';
export function demoLogin({ email, password }) {
  if (!demoEnabled) return null;
  if (email === 'admin@cyberintel.local' && password === 'Admin@123') return { token: 'local-demo', demo: true, user: { id: 0, name: 'Alex Morgan', email, role: 'ADMIN' } };
  return null;
}
