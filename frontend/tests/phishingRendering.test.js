import test from 'node:test';
import assert from 'node:assert/strict';
import { build } from 'esbuild';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

// Compile the real component with the project's existing Vite dependency.
// This render test runs entirely locally and makes no network requests.
const compiled = await build({ entryPoints: ['src/components/PhishingResults.jsx'], bundle: true, write: false, format: 'esm', platform: 'node', jsx: 'automatic' });
const { default: PhishingResults } = await import(`data:text/javascript;base64,${Buffer.from(compiled.outputFiles[0].text).toString('base64')}`);
const base = { url: 'https://example.com/', host: 'example.com', https: true, ipBased: false, score: 0, riskLevel: 'LOW', reasons: [], redirectIndicators: [] };
const render = result => renderToStaticMarkup(createElement(PhishingResults, { result }));

test('empty findings remain a qualified static estimate, not a safety verdict', () => {
  const html = render(base);
  assert.match(html, /not a verified phishing verdict/);
  assert.match(html, /A low score does not establish safety/);
  assert.match(html, /No configured phishing indicators/);
  assert.match(html, /No configured redirect parameters/);
  assert.match(html, /capped at 100/);
});

test('untrusted reasons and redirect candidates render as inert escaped text', () => {
  const payload = '<img src="https://example.test/tracker" onerror="alert(1)">';
  const html = render({ ...base, host: payload, reasons: [{ code: 'KEYWORD', severity: 'HIGH', description: payload, evidence: payload, contribution: 20 }], redirectIndicators: [{ parameter: payload, destination: 'javascript:alert(1)', host: null, crossHost: false, https: null, status: 'UNSUPPORTED_SCHEME' }] });
  assert.match(html, /&lt;img/);
  assert.doesNotMatch(html, /<(?:img|a|iframe|script)\b/);
  assert.match(html, /javascript:alert\(1\)/);
  assert.match(html, /Unsupported destination scheme/);
  assert.match(html, /Unknown/);
  assert.doesNotMatch(html, /Same host/);
});

test('redirect candidates report parsed structure without claiming observed behavior', () => {
  const html = render({ ...base, redirectIndicators: [{ parameter: 'next', destination: 'http://other.example/', host: 'other.example', crossHost: true, https: false, status: 'INSPECTED' }, { parameter: 'return', destination: '', host: null, crossHost: false, https: null, status: 'EMPTY' }] });
  assert.match(html, /Different host/);
  assert.match(html, /Parsed from URL text/);
  assert.match(html, /Empty destination/);
  assert.match(html, /No responses or redirects were observed/);
  assert.doesNotMatch(html, /href=|src=/);
});
