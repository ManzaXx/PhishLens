// Vistas y paneles en inglés (spec 3.1): la ruta no cambia, solo los rótulos.
import { test, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installDom, find, findAll, tag } from '../helpers/dom.js';
import { SAMPLES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';
import { setLang } from '../../src/i18n/index.js';
import { VIEW_LABELS, NAV_GROUPS, VIEWS } from '../../src/ui/route.js';

let dom;
let V;
before(async () => {
  dom = installDom();
  globalThis.matchMedia = () => ({ matches: true });
  globalThis.requestAnimationFrame = () => 0;
  V = {
    ...(await import('../../src/ui/views/analyst.js')),
    ...(await import('../../src/ui/views/simple.js')),
    ...(await import('../../src/ui/render.js')),
    ...(await import('../../src/ui/panels/history.js')),
    ...(await import('../../src/ui/panels/dashboard.js')),
    ...(await import('../../src/ui/panels/auth.js')),
  };
});
after(() => {
  dom.restore();
  delete globalThis.matchMedia;
  delete globalThis.requestAnimationFrame;
});
afterEach(() => setLang('es'));

const report = (prefix) => {
  const s = SAMPLES.find((x) => x.file.startsWith(prefix));
  return analyzeInput({ kind: 'eml', value: readFileSync(new URL(`../../samples/${s.file}`, import.meta.url), 'utf8') });
};
const links = (node) => findAll(node, (n) => n.localName === 'a' && n.className === 'nav-rail__link');

test('los rótulos de las vistas y grupos siguen al idioma; los ids no cambian', () => {
  assert.equal(VIEW_LABELS.panel, 'Panel');
  setLang('en');
  assert.deepEqual(VIEWS.map((v) => VIEW_LABELS[v]), [
    'Summary', 'Signals', 'Safe view', 'Authentication', 'Headers and route', 'Attachments',
    'URLs', 'IOCs', 'Campaigns', 'ATT&CK', 'Dashboard', 'History',
  ]);
  assert.deepEqual(NAV_GROUPS.map((g) => g.label), ['Email', 'Intelligence', 'History']);
  assert.deepEqual(NAV_GROUPS.flatMap((g) => g.views), VIEWS);
  assert.ok(Object.isFrozen(VIEW_LABELS));
});

test('en inglés, el modo analista rotula la navegación y deja los enlaces en #analista/…', () => {
  setLang('en');
  const view = V.renderAnalyst(report('03'), 'senales');
  const nav = find(view, tag('nav'));
  assert.equal(nav.getAttribute('aria-label'), 'Report sections');
  const rail = links(view);
  assert.ok(rail.some((a) => a.textContent.startsWith('Signals') && a.getAttribute('href') === '#analista/senales'));
  assert.ok(rail.some((a) => a.textContent.startsWith('Dashboard') && a.getAttribute('href') === '#analista/panel'));
  assert.equal(find(view, tag('h2')).textContent, 'Signals');
  const side = find(view, tag('aside'));
  assert.equal(side.getAttribute('aria-label'), 'Report context');
  assert.match(side.textContent, /Risk by category/);
});

test('en inglés: barra del informe con «Export» y «Analyze another», y el modo sencillo', () => {
  setLang('en');
  const box = document.createElement('section');
  V.renderReport(box, report('03'), { mode: 'simple' });
  const buttons = findAll(box, tag('button')).map((b) => b.textContent);
  assert.ok(buttons.includes('Export'), buttons.join(' | '));
  assert.ok(buttons.includes('Analyze another'));
  assert.ok(buttons.includes('See all the details (analyst mode)'));
  assert.deepEqual(V.exportItems().map((i) => i.text), ['Download report (JSON)', 'Download STIX 2.1', 'Copy IOCs', 'Forensic report']);
  assert.match(box.textContent, /What to do now/);
});

test('en inglés: cada vista del analista se pinta sin lanzar y con su título traducido', () => {
  setLang('en');
  const r = report('03');
  for (const v of ['resumen', 'senales', 'vista-segura', 'autenticacion', 'cabeceras', 'urls', 'iocs', 'attack']) {
    const view = V.renderAnalyst(r, v);
    assert.equal(find(view, tag('h2')).textContent, VIEW_LABELS[v], v);
  }
});

test('en inglés: historial con fechas en inglés, plurales y diálogo de borrado', () => {
  setLang('en');
  const item = { id: 'a', name: 'x.eml', savedAt: '2026-11-11T10:00:00Z', report: { level: 'high', email: { subject: 'S', from: { address: 'a@b.c' } } } };
  const panel = V.historyPanel(null, { history: { page: { items: [item], total: 1, skipped: 1, offset: 0 }, totalAll: 1 } });
  const text = panel.textContent;
  assert.match(text, /Showing 1–1 of 1/);
  assert.match(text, /1 saved entry could not be read and was skipped\./);
  assert.match(text, /Delete the 1 saved analysis\? This cannot be undone\./);
  assert.match(text, /11\/11\/2026/);
  const del = findAll(panel, tag('button')).find((b) => b.textContent === 'Delete');
  assert.equal(del.getAttribute('aria-label'), 'Delete x.eml');
});

test('en inglés: panel vacío y autenticación', () => {
  setLang('en');
  const dash = V.dashboardPanel(null, { historyEnabled: false });
  assert.match(dash.textContent, /Nothing saved yet\./);
  assert.ok(findAll(dash, tag('button')).some((b) => b.textContent === 'Turn on history'));
  const auth = V.authPanel(report('03'));
  assert.match(auth.textContent, /SPF, DKIM and DMARC/);
  assert.match(auth.textContent, /Check locally/);
});

test('en inglés: los avisos de cada salto de la ruta salen traducidos', async () => {
  const { headersPanel } = await import('../../src/ui/panels/headers.js');
  const { hopWarningCodes } = await import('../../src/detectors/route.js');
  const route = [{ helo: 'a', by: 'b', time: 2e12 }, { helo: 'c', by: 'd', entry: true, ip: '10.0.0.1', time: 1e12 }];
  assert.deepEqual(hopWarningCodes(route), [[], ['route.warn.entry', 'route.warn.private-ip', 'route.warn.backwards']]);
  setLang('en');
  const text = headersPanel({ email: { route } }).textContent;
  assert.match(text, /Entry to the receiving server/);
  assert.match(text, /Private IP at the boundary/);
  assert.match(text, /Time earlier than the previous hop/);
});

test('en inglés: el tipo real de un adjunto sale traducido', async () => {
  const { attachmentsPanel } = await import('../../src/ui/panels/attachments.js');
  setLang('en');
  const report = { findings: [], email: { attachments: [{ filename: 'a.pdf', contentType: 'application/pdf', size: 3, inspection: { realType: 'pe', realLabel: 'Ejecutable de Windows' } }] } };
  assert.match(attachmentsPanel(report).textContent, /Windows executable/);
});
