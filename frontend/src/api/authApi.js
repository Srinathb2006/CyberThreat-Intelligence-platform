import api from './axios';
import { demoEnabled } from '../utils/session';
export async function login(credentials) {
  if (demoEnabled) {
    const { demoLogin } = await import('./demoAuth');
    const result = demoLogin(credentials);
    if (result) return result;
  }
  return (await api.post('/auth/login', credentials)).data;
}
export async function register(details) { return (await api.post('/auth/register', details)).data; }
export async function getCurrentUser() { return (await api.get('/auth/me')).data; }
