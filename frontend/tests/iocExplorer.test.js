import test from 'node:test';
import assert from 'node:assert/strict';
import { matchState, pageRows } from '../src/utils/iocExplorer.js';

test('IOC match state distinguishes an intelligence match from review and absence', () => {
  assert.deepEqual(matchState([]), { label: 'No intelligence match', tone: 'neutral' });
  assert.equal(matchState([{ status: 'NO_MATCH' }]).label, 'No match after review');
  assert.equal(matchState([{ status: 'REVIEW' }]).label, 'Review recorded');
  const state = matchState([{ status: 'MATCHED', severity: 'HIGH', threatName: 'Example family' }]);
  assert.equal(state.label, 'Matched');
  assert.equal(state.tone, 'high');
});

test('IOC pagination returns a bounded page without mutating the source list', () => {
  const rows = Array.from({ length: 27 }, (_, id) => ({ id }));
  assert.deepEqual(pageRows(rows, 1).map(row => row.id), [25, 26]);
  assert.equal(rows.length, 27);
});
