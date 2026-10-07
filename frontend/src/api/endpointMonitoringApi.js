import api from './axios';

export async function listEndpoints(signal) {
  return (await api.get('/endpoints', { signal })).data;
}

export async function registerEndpoint(payload) {
  return (await api.post('/endpoints', payload)).data;
}

export async function getEndpoint(endpointId, signal) {
  return (await api.get(`/endpoints/${encodeURIComponent(endpointId)}`, { signal })).data;
}

export async function getEndpointEvents(endpointId, suspiciousOnly = false, signal) {
  return (await api.get(`/endpoints/${encodeURIComponent(endpointId)}/events`, { params: { suspiciousOnly }, signal })).data;
}
