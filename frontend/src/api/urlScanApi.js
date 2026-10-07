import api from './axios';

export async function createUrlScan(url, signal) {
  return (await api.post('/url-scans', { url }, { signal })).data;
}
export async function listUrlScans(signal) {
  return (await api.get('/url-scans', { signal })).data;
}
export async function getUrlScan(scanId, signal) {
  return (await api.get(`/url-scans/${encodeURIComponent(scanId)}`, { signal })).data;
}
