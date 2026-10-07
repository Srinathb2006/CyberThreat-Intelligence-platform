import api from './axios';

export async function getScanHistory({ search, packageName, status, riskLevel, signal } = {}) {
  const params = new URLSearchParams();
  if (search) params.set('search', search);
  if (packageName) params.set('packageName', packageName);
  if (status && status !== 'All') params.set('status', status);
  if (riskLevel && riskLevel !== 'All') params.set('riskLevel', riskLevel);
  return (await api.get('/scan-history', { params, signal })).data;
}

export async function getScanHistoryById(scanId, signal) {
  return (await api.get(`/scan-history/${scanId}`, { signal })).data;
}

export async function getDashboardStats(signal) {
  return (await api.get('/dashboard/stats', { signal })).data;
}
