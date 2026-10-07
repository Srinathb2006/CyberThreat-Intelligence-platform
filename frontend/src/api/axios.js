import axios from 'axios';
import { readSession, clearSession } from '../utils/session';
const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:7070/api', timeout: 15000 });
api.interceptors.request.use(config => { const session = readSession(); if (session && !session.demo) config.headers.Authorization = `Bearer ${session.token}`; return config; });
api.interceptors.response.use(response => response, error => {
  if (error.response?.status === 401 && !error.config.url.startsWith('/auth/login')) { clearSession(); window.dispatchEvent(new Event('auth-expired')); }
  return Promise.reject(error);
});
export default api;
