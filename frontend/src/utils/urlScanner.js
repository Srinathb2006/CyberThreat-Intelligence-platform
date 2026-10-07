export const URL_MAX_LENGTH = 2048;

// Convenience checks only; the backend performs authoritative validation.
export function validateScanUrl(value) {
  if (typeof value !== 'string' || !value) return 'Enter a URL to analyze.';
  if (value.length > URL_MAX_LENGTH) return `URLs must be ${URL_MAX_LENGTH} characters or fewer.`;
  if (/[\s\u0000-\u001f\u007f\\]/u.test(value)) return 'Remove whitespace, control characters, and backslashes from the URL.';
  if (!/^https?:\/\//i.test(value)) return 'Enter an absolute URL beginning with http:// or https://.';
  try {
    const parsed = new URL(value);
    if (!parsed.hostname) return 'Enter a URL with a valid host.';
    if (parsed.username || parsed.password) return 'URLs containing usernames or passwords are not accepted.';
  } catch { return 'Enter a valid HTTP or HTTPS URL.'; }
  return null;
}

export function mergeUrlHistory(rows, result) {
  return [result, ...rows.filter(row => row.scanId !== result.scanId)]
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt) || Number(b.scanId) - Number(a.scanId))
    .slice(0, 50);
}
