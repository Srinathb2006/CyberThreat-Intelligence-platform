import api from './axios';

export async function getAlerts({ status, severity, search, signal } = {}) {
  const params = new URLSearchParams();
  if (status && status !== 'All') params.set('status', status);
  if (severity && severity !== 'All') params.set('severity', severity);
  if (search) params.set('search', search);
  return (await api.get('/alerts', { params, signal })).data;
}

export async function getAlertById(id, signal) {
  return (await api.get(`/alerts/${id}`, { signal })).data;
}

export async function updateAlertStatus(id, { status, notes }, signal) {
  return (await api.patch(`/alerts/${id}/status`, { status, notes }, { signal })).data;
}

export async function resolveAlert(id, { notes, resolvedBy } = {}, signal) {
  return (await api.post(`/alerts/${id}/resolve`, { notes, resolvedBy }, { signal })).data;
}

export async function getAlertStats(signal) {
  return (await api.get('/alerts/stats', { signal })).data;
}

export async function generateAlerts(scanId, signal) {
  return (await api.post(`/alerts/generate/${scanId}`, null, { signal })).data;
}
