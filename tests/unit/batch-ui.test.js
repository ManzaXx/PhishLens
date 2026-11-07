// Lote en la UI (spec 2.3, §5.2): selector de correo encima del informe en los dos modos.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll, tag } from '../helpers/dom.js';
import { BATCHES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeBatch } from '../../src/core/batch.js';
import { buildGraph } from '../../src/intel/graph.js';
import { findCampaigns } from '../../src/intel/campaigns.js';

let dom;
let batchBar;
let renderReport;
let batch;
before(async () => {
  dom = installDom();
  globalThis.matchMedia = () => ({ matches: true });
  globalThis.requestAnimationFrame = () => 0;
  ({ batchBar } = await import('../../src/ui/components/batch-bar.js'));
  ({ renderReport } = await import('../../src/ui/render.js'));
  const files = BATCHES[0].files.map((f) => ({ name: f.split('/').pop(), size: 1, text: async () => SAMPLE_TEXTS[f] }));
  const out = await analyzeBatch(files, { yieldFn: async () => {} });
  batch = { ...out, graph: buildGraph(out.entries), campaigns: findCampaigns(out.entries), current: out.entries[0].key };
});
after(() => dom.restore());

const items = [
  { key: 'a', name: 'uno.eml', level: 'critical', label: 'Phishing casi seguro', score: 91 },
  { key: 'b', name: 'dos\u202E.eml', level: 'safe', label: 'Probablemente legítimo', score: 0 },
  { key: 'c', name: 'tres.eml', level: 'phishing', label: 'Probable phishing', score: 64 },
];

test('batchBar: una opción por correo, la actual seleccionada y un resumen en texto', () => {
  const bar = batchBar({ items, current: 'c', campaigns: 1, skipped: 0 });
  const select = find(bar, tag('select'));
  assert.equal(select.getAttribute('id'), 'batch-email');
  const label = find(bar, tag('label'));
  assert.equal(label.getAttribute('for'), 'batch-email');
  assert.equal(label.textContent, 'Correo del lote');
  const options = findAll(select, tag('option'));
  assert.deepEqual(options.map((o) => o.getAttribute('value')), ['a', 'b', 'c']);
  assert.equal(options[0].textContent, 'uno.eml · Phishing casi seguro · 91/100');
  assert.ok(options[1].textContent.includes('⟦U+202E⟧'));
  assert.deepEqual(options.map((o) => o.hasAttribute('selected')), [false, false, true]);
  assert.equal(find(bar, (n) => n.className === 'batch-bar__summary').textContent, '3 correos · 1 campaña · 2 peligrosos');
});

test('batchBar: singulares y correos sin analizar', () => {
  const bar = batchBar({ items: items.slice(0, 1), current: 'a', campaigns: 0, skipped: 2 });
  assert.equal(find(bar, (n) => n.className === 'batch-bar__summary').textContent, '1 correo · 0 campañas · 1 peligroso · 2 sin analizar');
});

for (const mode of ['simple', 'analyst']) {
  test(`renderReport con lote (${mode}): la barra va encima del informe`, () => {
    const box = document.createElement('section');
    const entry = batch.entries[0];
    renderReport(box, entry.report, { mode, view: 'resumen', batch });
    const kids = box.children;
    assert.equal(kids[1].className, 'batch-bar');
    if (mode === 'analyst') {
      const nav = find(box, (n) => n.className === 'nav-rail');
      assert.ok(nav.textContent.includes('Campañas'));
    }
  });
}

test('sin lote no hay barra ni «Campañas»', () => {
  const box = document.createElement('section');
  renderReport(box, batch.entries[0].report, { mode: 'analyst', view: 'resumen' });
  assert.equal(find(box, (n) => n.className === 'batch-bar'), null);
  assert.ok(!find(box, (n) => n.className === 'nav-rail').textContent.includes('Campañas'));
});

test('el selector ordena los correos por nombre (la clave interna es un hash)', () => {
  const box = document.createElement('section');
  renderReport(box, batch.entries[0].report, { mode: 'simple', view: 'resumen', batch });
  const names = findAll(find(box, tag('select')), tag('option')).map((o) => o.textContent.split(' · ')[0]);
  assert.deepEqual(names, ['1-entrega-fallida.eml', '2-aviso-adjunto.eml', '3-aduana-retenido.eml', '4-aduana-recordatorio.eml']);
});
