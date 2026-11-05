// Rendimiento (spec 2.2, §8.4): el análisis termina y 25 MB tardan menos de 4 s.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeInput } from '../../src/core/engine.js';
import { buildEmail, SIZES } from './build.js';

const MAX_MS_25MB = 4000;

for (const [label, bytes] of SIZES) {
  test(`analiza un correo de ${label}`, () => {
    const raw = buildEmail(bytes);
    const start = performance.now();
    const report = analyzeInput({ kind: 'eml', value: raw });
    const ms = performance.now() - start;
    assert.ok(report.score >= 0 && report.score <= 100);
    assert.equal(report.email.attachments.length, 1);
    if (bytes > 20 * 1024 * 1024) assert.ok(ms < MAX_MS_25MB, `${label}: ${Math.round(ms)} ms`);
  });
}
