import api from './axios';

export async function searchIocs(filters = {}, signal) {
  const params = Object.fromEntries(Object.entries(filters).filter(([, value]) => value !== '' && value != null));
  return (await api.get('/ioc-explorer', { params, signal })).data;
}

export async function getIocDetails(iocId, signal) {
  return (await api.get(`/ioc-explorer/${encodeURIComponent(iocId)}`, { signal })).data;
}
