// renderReport: la franja «Qué se ha analizado» va en los dos modos, entre la barra del informe y el contenido,
// y no aparece en las vistas que no hablan de un correo (historial y panel). Las señales del modo analista
// llevan data-finding, el destino de «Ver la prueba».
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installDom, find, findAll } from '../helpers/dom.js';
import { analyzeInput } from '../../src/core/engine.js';

let dom;
let renderReport;
let findingsPanel;
before(async () => {
  dom = installDom();
  globalThis.matchMedia ??= () => ({ matches: true });
  globalThis.requestAnimationFrame ??= () => 0;
  ({ renderReport } = await import('../../src/ui/render.js'));
  ({ findingsPanel } = await import('../../src/ui/panels/findings.js'));
});
after(() => dom.restore());

const r03 = () => analyzeInput({ kind: 'eml', value: readFileSync(new URL('../../samples/03-phishing-banco.eml', import.meta.url), 'utf8') });
const strips = (box) => findAll(box, (n) => n.classList?.contains('analyzed'));

test('modo sencillo: el veredicto primero y la franja justo debajo', () => {
  const box = document.createElement('section');
  renderReport(box, r03(), { mode: 'simple', kind: 'eml' });
  assert.deepEqual(box.children.map((n) => n.className.split(' ')[0]), ['report__toolbar', 'simple']);
  const simple = box.children[1];
  assert.deepEqual(simple.children.slice(0, 2).map((n) => n.className.split(' ')[0]), ['verdict-card', 'analyzed']);
});

test('modo analista: la franja va entre la barra y la vista', () => {
  const box = document.createElement('section');
  renderReport(box, r03(), { mode: 'analyst', view: 'resumen', kind: 'eml' });
  assert.equal(box.children[1].className, 'analyzed');
});

test('modo analista: la franja va en las vistas de un correo y no en historial ni panel', () => {
  for (const [view, expected] of [['resumen', 1], ['senales', 1], ['cabeceras', 1], ['historial', 0], ['panel', 0]]) {
    const box = document.createElement('section');
    renderReport(box, r03(), { mode: 'analyst', view, kind: 'eml', history: { entries: [] }, dashboard: null });
    assert.equal(strips(box).length, expected, view);
  }
});

test('Señales: cada tarjeta lleva data-finding con su posición y es enfocable con tabindex -1', () => {
  const r = r03();
  const cards = findAll(findingsPanel(r), (n) => n.localName === 'article');
  assert.equal(cards.length, r.findings.length);
  const indexes = cards.map((c) => Number(c.getAttribute('data-finding'))).sort((a, b) => a - b);
  assert.deepEqual(indexes, r.findings.map((_, i) => i));
  assert.ok(cards.every((c) => c.getAttribute('tabindex') === '-1'));
  const first = find(findingsPanel(r), (n) => n.getAttribute?.('data-finding') === '0');
  assert.match(first.textContent, new RegExp(r.findings[0].title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('modo sencillo: la franja tampoco lleva siglas (SPF, DKIM, DMARC) en ninguna muestra', async () => {
  const { SAMPLES } = await import('../../samples/index.js');
  for (const s of SAMPLES) {
    const r = analyzeInput({ kind: 'eml', value: readFileSync(new URL(`../../samples/${s.file}`, import.meta.url), 'utf8') });
    const box = document.createElement('section');
    renderReport(box, r, { mode: 'simple', kind: 'eml' });
    const text = strips(box)[0].textContent;
    for (const word of ['SPF', 'DKIM', 'DMARC']) assert.ok(!text.includes(word), `${s.file}: «${word}»`);
  }
});

test('modo sencillo, muestra 03: «No supera alguna comprobación de origen»', () => {
  const box = document.createElement('section');
  renderReport(box, r03(), { mode: 'simple', kind: 'eml' });
  assert.match(strips(box)[0].textContent, /No supera alguna comprobación de origen/);
});
