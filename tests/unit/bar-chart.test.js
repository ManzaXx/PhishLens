// Gráficas del panel (spec 3.0, §3): SVG propio con lista blanca, su tabla y texto siempre en textContent.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll } from '../helpers/dom.js';

let dom;
let stackedBars;
let hBars;
before(async () => {
  dom = installDom();
  ({ stackedBars, hBars } = await import('../../src/ui/components/bar-chart.js'));
});
after(() => dom.restore());

const SERIES = [{ key: 'safe', label: 'Legítimo' }, { key: 'suspicious', label: 'Sospechoso' }, { key: 'phishing', label: 'Probable phishing' }, { key: 'critical', label: 'Phishing casi seguro' }];
const counts = (safe, suspicious, phishing, critical) => ({ safe, suspicious, phishing, critical });
const buckets = [{ label: '9 nov', counts: counts(1, 0, 2, 0) }, { label: '10 nov', counts: counts(0, 1, 0, 3) }];
const attr = (n, k) => n.getAttribute?.(k) ?? null;
const local = (n) => n.localName ?? n.tagName?.toLowerCase();
const rects = (root) => findAll(root, (n) => local(n) === 'rect' && /chart__bar--/.test(attr(n, 'class') ?? ''));

test('stackedBars: un rect por segmento no vacío, con su <title> y su clase de serie', () => {
  const fig = stackedBars({ caption: 'Niveles en el tiempo', buckets, series: SERIES });
  const bars = rects(fig);
  assert.equal(bars.length, 4);
  assert.deepEqual(bars.map((b) => attr(b, 'class')), ['chart__bar chart__bar--safe', 'chart__bar chart__bar--phishing', 'chart__bar chart__bar--suspicious', 'chart__bar chart__bar--critical']);
  const titles = findAll(fig, (n) => local(n) === 'title').map((t) => t.textContent);
  assert.ok(titles.includes('9 nov: 2 Probable phishing'), titles.join(' | '));
  assert.equal(attr(find(fig, (n) => local(n) === 'svg'), 'role'), 'img');
});

test('stackedBars: 2 px entre segmentos y el de arriba con esquinas de 4 px', () => {
  const fig = stackedBars({ caption: 'N', buckets: [{ label: 'a', counts: counts(2, 2, 0, 0) }], series: SERIES });
  const [low, high] = rects(fig);
  const lowTop = Number(attr(low, 'y'));
  const highBottom = Number(attr(high, 'y')) + Number(attr(high, 'height'));
  assert.ok(Math.abs(lowTop - highBottom - 2) < 0.01, `hueco ${lowTop - highBottom}`);
  assert.equal(attr(high, 'rx'), '4');
  assert.equal(attr(low, 'rx'), null);
});

test('stackedBars: tabla con una fila por cubo y la columna Total; leyenda con texto', () => {
  const fig = stackedBars({ caption: 'Niveles en el tiempo', buckets, series: SERIES });
  const head = findAll(fig, (n) => local(n) === 'th').map((n) => n.textContent);
  assert.deepEqual(head, ['Fecha', 'Legítimo', 'Sospechoso', 'Probable phishing', 'Phishing casi seguro', 'Total']);
  const rows = findAll(fig, (n) => local(n) === 'tr' && local(n.parentNode) === 'tbody');
  assert.equal(rows.length, 2);
  assert.deepEqual(findAll(rows[1], (n) => local(n) === 'td').map((n) => n.textContent), ['10 nov', '0', '1', '0', '3', '4']);
  const legend = find(fig, (n) => attr(n, 'class') === 'chart__legend');
  assert.match(legend.textContent, /Legítimo.*Sospechoso.*Probable phishing.*Phishing casi seguro/);
});

test('stackedBars: todo a cero no pinta barras ni deja NaN', () => {
  const fig = stackedBars({ caption: 'N', buckets: [{ label: 'a', counts: counts(0, 0, 0, 0) }], series: SERIES });
  assert.equal(rects(fig).length, 0);
  for (const n of findAll(fig, (x) => local(x) === 'rect' || local(x) === 'line' || local(x) === 'text')) {
    for (const k of ['x', 'y', 'width', 'height', 'x1', 'x2', 'y1', 'y2']) assert.ok(!String(attr(n, k)).includes('NaN'), k);
  }
});

test('Review Focus 3: una etiqueta con <script>, RLO y 10.000 caracteres va como texto, recortada en el SVG y entera en la tabla', () => {
  const evil = `<script>x</script>\u202Eabc${'a'.repeat(10000)}`;
  const fig = hBars({ caption: 'Remitentes', rows: [{ label: evil, value: 3 }] });
  assert.equal(findAll(fig, (n) => local(n) === 'script').length, 0);
  const svgText = findAll(fig, (n) => local(n) === 'text').map((n) => n.textContent).find((t) => t.startsWith('<script>'));
  assert.ok(svgText.length < 100 && svgText.endsWith('…'), `largo ${svgText.length}`);
  assert.match(svgText, /⟦U\+202E⟧/);
  const cellText = findAll(fig, (n) => local(n) === 'td').map((n) => n.textContent).find((t) => t.startsWith('<script>'));
  assert.ok(cellText.length > 10000);
});

test('hBars: la barra más larga ocupa todo el ancho útil y el valor va en texto', () => {
  const fig = hBars({ caption: 'Técnicas', rows: [{ label: 'T1566', value: 8, detail: 'Initial Access' }, { label: 'T1036', value: 2 }] });
  const [a, b] = findAll(fig, (n) => local(n) === 'rect' && attr(n, 'class') === 'chart__hbar');
  assert.equal(Number(attr(b, 'width')) * 4, Number(attr(a, 'width')));
  const texts = findAll(fig, (n) => local(n) === 'text').map((n) => n.textContent);
  assert.ok(texts.includes('8') && texts.includes('2'));
  const head = findAll(fig, (n) => local(n) === 'th').map((n) => n.textContent);
  assert.deepEqual(head, ['Nombre', 'Detalle', 'Veces']);
});

test('solo etiquetas SVG de la lista blanca', () => {
  const ok = new Set(['svg', 'g', 'line', 'circle', 'rect', 'polygon', 'path', 'text', 'title']);
  for (const fig of [stackedBars({ caption: 'N', buckets, series: SERIES }), hBars({ caption: 'N', rows: [{ label: 'a', value: 1 }] })]) {
    const svgRoot = find(fig, (n) => local(n) === 'svg');
    for (const n of findAll(svgRoot, (x) => x.nodeType === 1)) assert.ok(ok.has(local(n)), local(n));
  }
});
