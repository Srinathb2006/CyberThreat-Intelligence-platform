export const text = value => value == null || value === '' ? '—' : String(value);
export const dateTime = value => value ? new Date(value).toLocaleString() : 'Never reported';

export function riskTone(level) {
  const normalized = String(level || '').toUpperCase();
  if (normalized === 'CRITICAL' || normalized === 'HIGH') return 'critical';
  if (normalized === 'MEDIUM') return 'medium';
  if (normalized === 'LOW') return 'low';
  return 'neutral';
}

export function statusTone(status) {
  return String(status || '').toUpperCase() === 'ONLINE' ? 'low' : 'neutral';
}

export function payloadForRegistration(values) {
  return {
    hostname: values.hostname.trim(),
    deviceName: values.deviceName.trim(),
    operatingSystem: values.operatingSystem.trim(),
    platform: values.platform.trim(),
    ...(values.status ? { status: values.status } : {}),
  };
}
