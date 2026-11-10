// Vista «Panel» (spec 3.0, §3): cifras, gráficas con tabla, IOCs que lanzan la búsqueda y campañas.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll } from '../helpers/dom.js';
import { SAMPLES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeInput } from '../../src/core/engine.js';
import { slimReport } from '../../src/storage/schema.js';
import { historyStats } from '../../src/intel/stats.js';
import { createHistoryControl } from '../../src/ui/history-control.js';
import { memoryBackend } from '../../src/storage/backends.js';

let dom;
let dashboardPanel;
let dashboardData;
before(async () => {
  dom = installDom();
  ({ dashboardPanel } = await import('../../src/ui/panels/dashboard.js'));
  ({ dashboardData } = await import('../../src/ui/dashboard-data.js'));
});
after(() => dom.restore());

const NOW = new Date('2026-11-10T12:00:00Z');
const report = (id) => slimReport(analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id] }));
const entries = SAMPLES.map((s, i) => ({ id: `e${i}`, savedAt: new Date(NOW - i * 86400000).toISOString(), sha256: i.toString(16).padStart(64, '0'), report: report(s.id) }));
const twice = [...entries, { ...entries[2], id: 'dup', sha256: 'f'.repeat(64) }];
const batches = [{ id: 'b', savedAt: '2026-11-09T10:00:00.000Z', emails: [], campaigns: [{ id: 'c', name: 'Campaña 1', reasons: ['Mismo dominio de envío'], techniques: [], emails: [entries[1].sha256, entries[2].sha256] }] }];
const stats = historyStats(twice, { now: NOW, batches });
const attr = (n, k) => n.getAttribute?.(k) ?? null;
const text = (n) => n.textContent;

test('historial apagado: estado vacío con el texto exacto y «Activar historial»', () => {
  const panel = dashboardPanel(entries[0].report, { historyEnabled: false, dashboard: null });
  assert.match(text(panel), /Aún no hay nada guardado\.\s*Activa el historial y analiza algún correo para ver aquí lo que te llega\./);
  const btn = find(panel, (n) => attr(n, 'data-action') === 'history-enable');
  assert.equal(text(btn), 'Activar historial');
});

test('cinco fichas con su número y su rótulo', () => {
  const panel = dashboardPanel(entries[0].report, { historyEnabled: true, dashboard: { stats } });
  const tiles = findAll(panel, (n) => attr(n, 'class') === 'stat-tile');
  assert.deepEqual(tiles.map((t) => text(find(t, (n) => attr(n, 'class') === 'stat-tile__label'))),
    ['Análisis guardados', 'Probable phishing o peor', 'Campañas', 'IOCs distintos', 'Con adjunto peligroso']);
  assert.equal(text(find(tiles[0], (n) => attr(n, 'class') === 'stat-tile__value')), '14');
  assert.match(text(find(tiles[4], (n) => attr(n, 'class') === 'stat-tile__value')), /^\d+ %$/);
});

test('las gráficas son figure.chart con su tabla', () => {
  const panel = dashboardPanel(entries[0].report, { historyEnabled: true, dashboard: { stats } });
  const captions = findAll(panel, (n) => attr(n, 'class') === 'chart__caption').map(text);
  assert.deepEqual(captions, ['Niveles en el tiempo', 'Técnicas ATT&CK más vistas', 'Remitentes más frecuentes', 'Dominios de envío más frecuentes']);
  for (const fig of findAll(panel, (n) => attr(n, 'class') === 'chart')) assert.ok(find(fig, (n) => n.localName === 'table'));
});

test('cada IOC repetido es un botón que lanza la búsqueda, defanged en el texto y en bruto en data-ioc', () => {
  const panel = dashboardPanel(entries[0].report, { historyEnabled: true, dashboard: { stats } });
  const btns = findAll(panel, (n) => attr(n, 'data-action') === 'dashboard-search');
  assert.ok(btns.length > 0);
  const dom1 = btns.find((b) => /\./.test(attr(b, 'data-ioc')) && !/^[0-9a-f]+$/.test(attr(b, 'data-ioc')));
  assert.ok(dom1, 'algún dominio o IP');
  assert.ok(text(dom1).includes('[.]'), text(dom1));
  assert.equal(findAll(panel, (n) => n.localName === 'a').length, 0, 'ningún enlace');
  // WCAG 2.5.3: el nombre accesible es el texto visible (axe label-content-name-mismatch).
  for (const b of btns) assert.equal(attr(b, 'aria-label'), null);
});

test('Review Focus 2: sin IOCs repetidos lo dice en texto', () => {
  const panel = dashboardPanel(entries[0].report, { historyEnabled: true, dashboard: { stats: historyStats([entries[0]], { now: NOW }) } });
  assert.match(text(panel), /Ningún IOC aparece en más de un análisis\./);
});

test('campañas recientes: nombre, fecha, número de correos, motivos y «Abrir el último correo»', () => {
  const panel = dashboardPanel(entries[0].report, { historyEnabled: true, dashboard: { stats } });
  const box = find(panel, (n) => (attr(n, 'class') ?? '').split(' ').includes('dashboard__campaigns'));
  assert.match(text(box), /Campaña 1/);
  assert.match(text(box), /2 correos/);
  assert.match(text(box), /Mismo dominio de envío/);
  const open = find(box, (n) => attr(n, 'data-action') === 'dashboard-open');
  assert.equal(text(open), 'Abrir el último correo');
  assert.equal(attr(open, 'data-sha'), entries[1].sha256);
});

test('Review Focus 4: dashboardData memoriza por revisión y sigue los cambios del historial', async () => {
  const ctl = createHistoryControl({ storage: null, version: '3.0.0', open: async () => memoryBackend() });
  const cache = {};
  assert.equal(await dashboardData(ctl, cache, NOW), null, 'apagado');
  await ctl.enable();
  const input = (id) => ({ kind: 'eml', value: SAMPLE_TEXTS[id] });
  await ctl.record(input('03-phishing-banco'), analyzeInput(input('03-phishing-banco')), 'a.eml');
  const a = await dashboardData(ctl, cache, NOW);
  assert.equal(a.stats.totals.analyses, 1);
  assert.equal(await dashboardData(ctl, cache, NOW), a, 'misma revisión → mismo objeto');
  await ctl.record(input('04-phishing-correos'), analyzeInput(input('04-phishing-correos')), 'b.eml');
  assert.equal((await dashboardData(ctl, cache, NOW)).stats.totals.analyses, 2);
  await ctl.clear();
  const after = await dashboardData(ctl, cache, NOW);
  assert.equal(after.stats.totals.analyses, 0, 'tras borrar todo, cero');
});

test('revisión final: la cifra de campañas cuenta todos los lotes guardados, no solo los 20 últimos', async () => {
  const backend = memoryBackend();
  const ctl = createHistoryControl({ storage: null, version: '3.0.0', open: async () => backend });
  await ctl.enable();
  const hex = (i) => i.toString(16).padStart(64, '0');
  for (let i = 0; i < 25; i++) {
    await backend.put('batches', { id: `b${i}`, savedAt: new Date(NOW.getTime() - i * 60000).toISOString(), emails: [hex(i)], campaigns: [{ id: 'c', name: 'Campaña 1', reasons: [], techniques: [], emails: [hex(i), hex(i + 100)] }] });
  }
  ctl.disable();
  await ctl.enable();
  const { stats } = await dashboardData(ctl, {}, NOW);
  assert.equal(stats.totals.campaigns, 25);
  assert.equal(stats.campaigns.length, 5);
});
