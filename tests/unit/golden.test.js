import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildGolden, GOLDEN_PATH } from '../helpers/golden.js';

test('los informes de las 7 muestras no cambian (golden v2.1)', () => {
  assert.deepEqual(buildGolden(), JSON.parse(readFileSync(GOLDEN_PATH, 'utf8')));
});
