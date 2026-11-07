// Rendimiento (spec 2.2, §8.4): el análisis termina y 25 MB tardan menos de 4 s.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeInput } from '../../src/core/engine.js';
import { buildEmail, SIZES } from './build.js';
import { buildGraph } from '../../src/intel/graph.js';
import { layoutGraph } from '../../src/intel/layout.js';

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

test('grafo enorme: 50 correos con 200 enlaces cada uno se construye y se dispone en menos de 1 s', () => {
  const entries = Array.from({ length: 50 }, (_, i) => ({
    key: `k${String(i).padStart(2, '0')}`, name: `${i}.eml`,
    report: { level: 'phishing', email: { from: { address: `a@d${i}.test` }, links: Array.from({ length: 200 }, (_, j) => ({ href: `https://h${i}-${j}.test/p` })) } },
  }));
  const start = performance.now();
  const layout = layoutGraph(buildGraph(entries));
  const ms = performance.now() - start;
  assert.equal(layout.nodes.length, 150);
  assert.ok(ms < 1000, `${Math.round(ms)} ms`);
});
