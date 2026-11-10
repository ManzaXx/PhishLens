// Rendimiento (spec 2.2, §8.4): el análisis termina y 25 MB tardan menos de 4 s.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeInput } from '../../src/core/engine.js';
import { buildEmail, SIZES } from './build.js';
import { buildGraph } from '../../src/intel/graph.js';
import { layoutGraph } from '../../src/intel/layout.js';
import { historyStats } from '../../src/intel/stats.js';
import { slimReport } from '../../src/storage/schema.js';
import { SAMPLES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';

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

test('panel: historyStats con 500 entradas de 200 IOCs cada una en menos de 300 ms (spec 3.0, §1.3)', () => {
  const reports = SAMPLES.map((x) => slimReport(analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[x.id] })));
  const now = new Date('2026-11-10T12:00:00Z');
  const entries = Array.from({ length: 500 }, (_, i) => {
    const report = structuredClone(reports[i % reports.length]);
    report.iocs = { ...report.iocs, domains: Array.from({ length: 200 }, (_, j) => `d${(i * 7 + j) % 900}.test`) };
    return { id: `e${i}`, savedAt: new Date(now.getTime() - (i % 60) * 86400000).toISOString(), sha256: i.toString(16).padStart(64, '0'), report };
  });
  const start = performance.now();
  const s = historyStats(entries, { now });
  const ms = performance.now() - start;
  assert.equal(s.totals.analyses, 500);
  assert.equal(s.iocs.length, 20);
  assert.ok(ms < 300, `${Math.round(ms)} ms`);
});
