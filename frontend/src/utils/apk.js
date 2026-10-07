export const activeStatuses = ['QUEUED', 'RUNNING'];
export const formatBytes = bytes => bytes == null ? 'Not available' : bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(2)} KB` : `${(bytes / 1024 / 1024).toFixed(2)} MB`;
export const formatDate = value => value ? new Date(value).toLocaleString() : '—';
export const APK_MAX_BYTES = 50 * 1024 * 1024;
export function validateApk(file, maxBytes = APK_MAX_BYTES) {
  if (!file) return 'Choose an APK file first.';
  if (!/\.apk$/i.test(file.name)) return 'Only .apk files are accepted.';
  if (file.size === 0) return 'The file is empty.';
  if (file.size > maxBytes) return `The maximum file size is ${formatBytes(maxBytes)}.`;
  return null;
}
