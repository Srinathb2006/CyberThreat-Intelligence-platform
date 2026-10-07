import test from 'node:test';
import assert from 'node:assert/strict';
import { validateApk, formatBytes, APK_MAX_BYTES } from '../src/utils/apk.js';
test('rejects missing and empty files', () => { assert.match(validateApk(null), /Choose/); assert.match(validateApk({ name: 'empty.apk', size: 0 }), /empty/); });
for (const name of ['sample.exe', 'sample.zip', 'sample.rar', 'sample.jar', 'sample.apk.zip', 'sample']) {
  test(`rejects unsupported filename ${name}`, () => assert.match(validateApk({ name, size: 1 }), /Only .apk/));
}
test('accepts APK extension case insensitively at the configured boundary', () => { assert.equal(validateApk({ name: 'sample.APK', size: 10240 }, 10240), null); });
test('enforces the backend supplied maximum, not a fixed frontend maximum', () => { assert.match(validateApk({ name: 'sample.apk', size: 10241 }, 10240), /10.00 KB/); assert.equal(validateApk({ name: 'sample.apk', size: APK_MAX_BYTES + 1 }, APK_MAX_BYTES + 2), null); });
test('reports small byte sizes without rounding to zero megabytes', () => { assert.equal(formatBytes(512), '512 B'); assert.equal(formatBytes(4096), '4.00 KB'); assert.equal(formatBytes(52428800), '50.00 MB'); });
