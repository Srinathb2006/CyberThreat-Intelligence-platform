import api from './axios';

export async function analyzePhishing(url, signal) {
  return (await api.post('/phishing/analyze', { url }, { signal })).data;
}
