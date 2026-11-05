// La matriz de cobertura (docs/coverage-matrix.md) está al día y no se deja ninguna regla.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildMatrix, renderMatrix, ruleIds } from '../../tools/gen-coverage.mjs';
import { SAMPLES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';

test('docs/coverage-matrix.md coincide con la generada (npm run coverage)', () => {
  const disk = readFileSync(new URL('../../docs/coverage-matrix.md', import.meta.url), 'utf8');
  assert.equal(disk, renderMatrix(buildMatrix()));
});

test('la lista de reglas incluye todo lo que emiten las muestras y no incluye notas del parser', () => {
  const rules = new Set(ruleIds());
  for (const sample of SAMPLES) {
    const raw = readFileSync(new URL(`../../samples/${sample.file}`, import.meta.url), 'utf8');
    for (const f of analyzeInput({ kind: 'eml', value: raw }).findings) assert.ok(rules.has(f.id), `${f.id} falta en la matriz`);
  }
  assert.ok(!rules.has('mime.unterminated-multipart'), 'es una nota del parser, no una regla');
  for (const id of ['auth.spf', 'auth.dmarc', 'links.ip', 'links.insecure-login', 'language.urgency', 'input.no-headers']) assert.ok(rules.has(id), id);
});

test('cada regla está en un test o en una muestra, o la matriz la marca', () => {
  const rows = buildMatrix();
  assert.ok(rows.length >= 70, `solo ${rows.length} reglas`);
  for (const row of rows) {
    if (!row.tests.length && !row.samples.length) assert.equal(row.mark, '⚠️', row.id);
  }
});
