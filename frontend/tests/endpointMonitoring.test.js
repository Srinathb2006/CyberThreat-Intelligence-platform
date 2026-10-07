import test from 'node:test';
import assert from 'node:assert/strict';
import { payloadForRegistration, riskTone, statusTone } from '../src/utils/endpointMonitoring.js';

test('registration payload trims fields and leaves no optional status behind', () => {
  assert.deepEqual(payloadForRegistration({ hostname: ' host-1 ', deviceName: ' Analyst PC ', operatingSystem: ' Windows ', platform: ' win32 ', status: '' }), { hostname: 'host-1', deviceName: 'Analyst PC', operatingSystem: 'Windows', platform: 'win32' });
});

test('endpoint status and risk map to the workspace badge tones', () => {
  assert.equal(statusTone('ONLINE'), 'low');
  assert.equal(statusTone('offline'), 'neutral');
  assert.equal(riskTone('CRITICAL'), 'critical');
  assert.equal(riskTone('MEDIUM'), 'medium');
  assert.equal(riskTone('LOW'), 'low');
});
