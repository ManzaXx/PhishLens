import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildGolden, GOLDEN_PATH } from '../helpers/golden.js';

test('los informes de las muestras no cambian (golden)', () => {
  assert.deepEqual(buildGolden(), JSON.parse(readFileSync(GOLDEN_PATH, 'utf8')));
});
