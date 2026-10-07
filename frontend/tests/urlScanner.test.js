import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeUrlHistory, URL_MAX_LENGTH, validateScanUrl } from '../src/utils/urlScanner.js';

test('requires an explicit HTTP or HTTPS address', () => {
  for (const value of ['', null, 'example.com', '//example.com', 'file:///etc/passwd', 'javascript:alert(1)', 'data:text/html,test', 'ftp://example.com']) {
    assert.ok(validateScanUrl(value));
  }
});

test('rejects ambiguous input and embedded credentials before submitting', () => {
  for (const value of [' https://example.com', 'https://example.com\n', 'https://example.com/a b', 'https:\\example.com', 'https://example.com\\evil', 'https://user:secret@example.com', 'https://example.com:99999', 'https://', 'http://[not-an-ip]/']) {
    assert.ok(validateScanUrl(value), value);
  }
});

test('accepts suspicious addresses as data for static analysis without fetching', () => {
  for (const value of ['http://127.0.0.1/login', 'https://[::1]/verify?token=example#fragment', 'https://example.xyz/%6cogin', 'HTTP://example.com:8080/account', 'https://xn--bcher-kva.example/']) {
    assert.equal(validateScanUrl(value), null, value);
  }
});

test('enforces the URL length boundary', () => {
  const prefix = 'https://example.com/';
  const value = prefix + 'a'.repeat(URL_MAX_LENGTH - prefix.length);
  assert.equal(validateScanUrl(value), null);
  assert.ok(validateScanUrl(value + 'a'));
});

test('saved history remains newest first, deduplicated and bounded to 50', () => {
  const rows = Array.from({ length: 50 }, (_, index) => ({ scanId: index + 1, createdAt: '2026-10-07T00:00:00Z' }));
  const newest = { scanId: 51, createdAt: '2026-10-07T00:00:01Z' };
  const merged = mergeUrlHistory(rows, newest);
  assert.equal(merged.length, 50);
  assert.equal(merged[0], newest);
  assert.equal(merged.at(-1).scanId, 2);
  const replacement = { ...newest, status: 'COMPLETED' };
  const updated = mergeUrlHistory(merged, replacement);
  assert.equal(updated.length, 50);
  assert.equal(updated[0], replacement);
  assert.equal(updated.filter(row => row.scanId === 51).length, 1);
  assert.equal(rows.length, 50);
});
