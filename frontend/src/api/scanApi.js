import api from './axios';
export { validateApk, APK_MAX_BYTES } from '../utils/apk';
export async function getApkConfig(signal) { return (await api.get('/apk/config', { signal })).data; }
export async function uploadApk(file, { signal, onProgress } = {}) {
  const data = new FormData(); data.append('file', file);
  return (await api.post('/apk/upload', data, { signal, timeout: 120000, onUploadProgress: event => { if (event.total && onProgress) onProgress(Math.round(event.loaded / event.total * 100)); } })).data;
}
export async function listApkScans(signal) { return (await api.get('/apk-analysis', { signal })).data; }
export async function getApkScan(id, signal) { return (await api.get(`/apk-analysis/${id}`, { signal })).data; }
export async function startApkScan(id) { return (await api.post(`/apk-analysis/${id}/start`)).data; }
export async function cancelApkScan(id) { return (await api.post(`/apk-analysis/${id}/cancel`)).data; }

export async function runStaticAnalysis(scanId, mock = false, signal) {
  return (await api.post(`/static-analysis/${scanId}`, null, { params: { mock }, signal })).data;
}
export async function getStaticSummary(scanId, signal) {
  return (await api.get(`/static-analysis/${scanId}/summary`, { signal })).data;
}
export async function getMalwareFindings(scanId, { category, severity, signal } = {}) {
  const params = new URLSearchParams();
  if (category) params.set('category', category);
  if (severity) params.set('severity', severity);
  return (await api.get(`/static-analysis/${scanId}/findings`, { params, signal })).data;
}
export async function getIocs(scanId, { type, severity, signal } = {}) {
  const params = new URLSearchParams();
  if (type) params.set('type', type);
  if (severity) params.set('severity', severity);
  return (await api.get(`/static-analysis/${scanId}/iocs`, { params, signal })).data;
}
export async function getIocCountsByType(scanId, signal) {
  return (await api.get(`/static-analysis/${scanId}/iocs/by-type`, { signal })).data;
}
export async function getFindingCountsByCategory(scanId, signal) {
  return (await api.get(`/static-analysis/${scanId}/findings/by-category`, { signal })).data;
}

export async function runThreatIntelCorrelation(scanId, signal) {
  return (await api.post(`/threat-intelligence/correlate/${scanId}`, null, { signal })).data;
}

export async function getThreatIntelCorrelationSummary(scanId, signal) {
  return (await api.get(`/threat-intelligence/correlate/${scanId}/summary`, { signal })).data;
}

export async function getThreatIntelligence(params = {}, signal) {
  const searchParams = new URLSearchParams();
  if (params.type) searchParams.set('type', params.type);
  if (params.severity) searchParams.set('severity', params.severity);
  if (params.category) searchParams.set('category', params.category);
  if (params.source) searchParams.set('source', params.source);
  return (await api.get('/threat-intelligence', { params: searchParams, signal })).data;
}

export async function searchThreatIntelligence(indicator, signal) {
  return (await api.get('/threat-intelligence/search', { params: { indicator }, signal })).data;
}

export async function getThreatIntelligenceSources(signal) {
  return (await api.get('/threat-intelligence/sources', { signal })).data;
}

export async function importThreatIntelligence(file, signal) {
  const formData = new FormData();
  formData.append('file', file);
  return (await api.post('/threat-intelligence/import', formData, { signal, timeout: 60000 })).data;
}

export async function exportThreatIntelligence(signal) {
  return (await api.get('/threat-intelligence/export', { signal, responseType: 'blob' })).data;
}

export async function calculateRisk(scanId, signal) {
  return (await api.post(`/risk-correlation/${scanId}/calculate`, null, { signal })).data;
}

export async function getRiskAssessment(scanId, signal) {
  return (await api.get(`/risk-correlation/${scanId}`, { signal })).data;
}

export async function getRiskIndicators(scanId, signal) {
  return (await api.get(`/risk-correlation/${scanId}/indicators`, { signal })).data;
}

export async function getRiskBreakdown(scanId, signal) {
  return (await api.get(`/risk-correlation/${scanId}/breakdown`, { signal })).data;
}

export async function getRiskRecommendations(scanId, signal) {
  return (await api.get(`/risk-correlation/${scanId}/recommendations`, { signal })).data;
}
