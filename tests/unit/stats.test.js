// Estadísticas del panel (spec 3.0, §3): una pasada, sin depender del orden y sin lanzar con entradas raras.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeInput } from '../../src/core/engine.js';
import { slimReport } from '../../src/storage/schema.js';
import { historyStats } from '../../src/intel/stats.js';
import { shuffle } from '../helpers/batch.js';

const NOW = new Date('2026-11-10T12:00:00Z');
const DAY = 24 * 60 * 60 * 1000;
const iso = (daysAgo) => new Date(NOW.getTime() - daysAgo * DAY).toISOString();
const sha = (i) => i.toString(16).padStart(64, '0');
const entries = SAMPLES.map((s, i) => ({
  id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`, savedAt: iso(i), sha256: sha(i + 1),
  report: slimReport(analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[s.id] })),
}));
const BAD = new Set(['phishing', 'critical']);

test('cifras: análisis, probable phishing o peor y porcentaje con adjunto peligroso', () => {
  const s = historyStats(entries, { now: NOW });
  assert.equal(s.totals.analyses, entries.length);
  assert.equal(s.totals.phishingOrWorse, entries.filter((e) => BAD.has(e.report.level)).length);
  const dangerous = entries.filter((e) => e.report.findings.some((f) => f.detector === 'attachments' && f.severity === 'high')).length;
  assert.ok(dangerous > 0, 'alguna muestra tiene un adjunto peligroso');
  assert.equal(s.totals.dangerousPct, Math.round((100 * dangerous) / entries.length));
  assert.ok(s.totals.distinctIocs > 0);
});

test('línea de tiempo por días: 30 cubos consecutivos que acaban hoy y suman todos los análisis', () => {
  const { timeline } = historyStats(entries, { now: NOW });
  assert.equal(timeline.unit, 'day');
  assert.equal(timeline.buckets.length, 30);
  assert.equal(timeline.buckets.at(-1).start, '2026-11-10');
  assert.equal(timeline.buckets[0].start, '2026-10-12');
  const sum = timeline.buckets.reduce((n, b) => n + Object.values(b.counts).reduce((a, c) => a + c, 0), 0);
  assert.equal(sum, entries.length);
  assert.deepEqual(Object.keys(timeline.buckets[0].counts), ['safe', 'suspicious', 'phishing', 'critical']);
});

test('más de 30 días: cubos por semana que empiezan en lunes, 26 como mucho', () => {
  const old = entries.map((e, i) => ({ ...e, savedAt: iso(i * 40) }));
  const { timeline } = historyStats(old, { now: NOW });
  assert.equal(timeline.unit, 'week');
  assert.ok(timeline.buckets.length <= 26);
  for (const b of timeline.buckets) assert.equal(new Date(`${b.start}T00:00:00Z`).getUTCDay(), 1, b.start);
  assert.equal(timeline.buckets.at(-1).start, '2026-11-09');
});

test('IOCs repetidos: solo los que salen en dos o más análisis, sin URLs ni direcciones', () => {
  const twice = [...entries, { ...entries[2], id: '00000000-0000-4000-8000-000000000099', sha256: sha(99) }];
  const { iocs } = historyStats(twice, { now: NOW });
  assert.ok(iocs.length > 0);
  for (const i of iocs) {
    assert.ok(i.count >= 2);
    assert.ok(['domains', 'ips', 'hashes', 'sha1', 'md5'].includes(i.type), i.type);
  }
  for (let k = 1; k < iocs.length; k++) {
    const [a, b] = [iocs[k - 1], iocs[k]];
    assert.ok(a.count > b.count || (a.count === b.count && a.value <= b.value));
  }
  assert.ok(iocs.length <= 20);
});

test('remitentes y dominios: solo de correos sospechosos o peores', () => {
  const s = historyStats(entries, { now: NOW });
  const safeFrom = entries.filter((e) => e.report.level === 'safe').map((e) => e.report.email?.from?.address).filter(Boolean);
  for (const sf of safeFrom) assert.ok(!s.senders.some((x) => x.value === sf), sf);
  assert.ok(s.senders.length > 0 && s.senders.length <= 10);
  assert.ok(s.domains.length > 0 && s.domains.length <= 10);
});

test('técnicas: 10 como mucho, por veces y luego id, con su nombre y táctica', () => {
  const { techniques } = historyStats(entries, { now: NOW });
  assert.ok(techniques.length > 0 && techniques.length <= 10);
  assert.ok(techniques.every((t) => t.id && t.name && t.count >= 1));
  for (let k = 1; k < techniques.length; k++) assert.ok(techniques[k - 1].count >= techniques[k].count);
});

test('campañas: las 5 más recientes, con su número de correos y el sha del más reciente', () => {
  const batches = Array.from({ length: 7 }, (_, i) => ({
    id: `b${i}`, savedAt: iso(i), emails: [sha(1), sha(2)],
    campaigns: [{ id: `c${i}`, name: `Campaña ${i}`, reasons: ['Mismo dominio de envío'], techniques: [], emails: [sha(3), sha(2)] }],
  }));
  const { campaigns, totals } = historyStats(entries, { now: NOW, batches });
  assert.equal(totals.campaigns, 7);
  assert.equal(campaigns.length, 5);
  assert.deepEqual(campaigns.map((c) => c.name), ['Campaña 0', 'Campaña 1', 'Campaña 2', 'Campaña 3', 'Campaña 4']);
  assert.equal(campaigns[0].emails, 2);
  assert.equal(campaigns[0].latestSha, sha(2), 'sha(2) se guardó hace 1 día; sha(3), hace 2');
});

test('Review Focus 1: sin remitente, sin técnicas y con fecha futura no lanza', () => {
  const odd = [
    { id: 'x1', savedAt: iso(-5), sha256: sha(200), report: { level: 'critical', score: 90, findings: [], techniques: [] } },
    { id: 'x2', savedAt: 'no es fecha', sha256: sha(201), report: { level: 'safe', score: 0, findings: [], techniques: [], email: {} } },
  ];
  const s = historyStats(odd, { now: NOW });
  assert.equal(s.totals.analyses, 2);
  assert.equal(s.timeline.buckets.at(-1).counts.critical, 1, 'la fecha futura cuenta hoy');
  assert.deepEqual(s.senders, []);
});

test('Review Focus 2: una sola entrada da un cubo con 1 y ningún IOC repetido', () => {
  const s = historyStats([entries[0]], { now: NOW });
  const total = s.timeline.buckets.reduce((n, b) => n + Object.values(b.counts).reduce((a, c) => a + c, 0), 0);
  assert.equal(total, 1);
  assert.deepEqual(s.iocs, []);
  assert.equal(s.totals.dangerousPct, entries[0].report.findings.some((f) => f.detector === 'attachments' && f.severity === 'high') ? 100 : 0);
});

test('sin entradas: ceros y listas vacías', () => {
  const s = historyStats([], { now: NOW });
  assert.deepEqual(s.totals, { analyses: 0, phishingOrWorse: 0, campaigns: 0, distinctIocs: 0, dangerousPct: 0 });
  assert.equal(s.timeline.buckets.length, 30);
});

test('propiedad: el resultado no depende del orden de las entradas ni de los lotes', () => {
  const batches = [{ id: 'b', savedAt: iso(1), emails: [], campaigns: [{ id: 'c', name: 'C', reasons: [], techniques: [], emails: [sha(1), sha(2)] }] }];
  const expected = historyStats(entries, { now: NOW, batches });
  for (let seed = 1; seed <= 50; seed++) assert.deepEqual(historyStats(shuffle(entries, seed), { now: NOW, batches }), expected, `semilla ${seed}`);
});

test('revisión final: el mismo lote guardado dos veces es una sola campaña, la más reciente', () => {
  const lot = (savedAt, id) => ({ id, savedAt, emails: [sha(1), sha(2)], campaigns: [{ id: 'c', name: 'Campaña 1', reasons: ['Mismo dominio de envío: x[.]test'], techniques: [], emails: [sha(2), sha(1)] }] });
  const other = { id: 'b3', savedAt: iso(3), emails: [sha(3)], campaigns: [{ id: 'c', name: 'Campaña 1', reasons: [], techniques: [], emails: [sha(3), sha(4)] }] };
  const { campaigns, totals } = historyStats(entries, { now: NOW, batches: [lot(iso(5), 'b1'), lot(iso(1), 'b2'), other] });
  assert.equal(totals.campaigns, 2);
  assert.deepEqual(campaigns.map((c) => c.savedAt), [iso(1), iso(3)]);
});
