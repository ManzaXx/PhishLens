// Modo sencillo del informe (spec 2.3, §2): veredicto, pasos y porqué, sin jerga.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installDom, find, findAll, tag } from '../helpers/dom.js';
import { SAMPLES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';

let dom;
let renderSimple;
before(async () => {
  dom = installDom();
  ({ renderSimple } = await import('../../src/ui/views/simple.js'));
});
after(() => dom.restore());

const report = (prefix) => {
  const s = SAMPLES.find((x) => x.file.startsWith(prefix));
  return analyzeInput({ kind: 'eml', value: readFileSync(new URL(`../../samples/${s.file}`, import.meta.url), 'utf8') });
};
const has = (cls) => (n) => n.classList.contains(cls);

test('muestra 03: veredicto, tres pasos, señales y salida al modo analista', () => {
  const view = renderSimple(report('03'));
  assert.equal(find(view, tag('h2')).textContent, 'No te fíes: es phishing');
  const ol = find(view, tag('ol'));
  assert.equal(ol.children.length, 3);
  const rows = findAll(view, has('signal'));
  assert.ok(rows.length >= 1 && rows.length <= 5, String(rows.length));
  const button = find(view, (n) => n.getAttribute('data-action') === 'mode-analyst');
  assert.equal(button.localName, 'button');
  assert.equal(button.getAttribute('type'), 'button');
  assert.equal(button.textContent, 'Ver todos los detalles (modo analista)');
  // Orden: veredicto, pasos, porqué, botón.
  const order = view.children.map((n) => n.className.split(' ')[0]);
  assert.deepEqual(order, ['verdict-card', 'simple__section', 'simple__section', 'simple__more']);
  const headings = findAll(view, tag('h3')).map((n) => n.textContent);
  assert.deepEqual(headings, ['Qué hacer ahora', 'Por qué lo decimos']);
});

test('muestra 01: estado vacío y ninguna fila de señal', () => {
  const view = renderSimple(report('01'));
  assert.ok(find(view, has('empty-state')));
  assert.match(view.textContent, /Sin señales de riesgo/);
  assert.equal(findAll(view, has('signal')).length, 0);
});

test('ningún texto visible del modo sencillo lleva jerga', () => {
  for (const s of SAMPLES) {
    const text = renderSimple(report(s.file.slice(0, 2))).textContent;
    for (const word of ['SPF', 'DKIM', 'DMARC', 'T1']) assert.ok(!text.includes(word), `${s.file}: «${word}»`);
  }
});
