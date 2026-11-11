// Componentes en inglés (spec 3.1): mismos componentes, textos del diccionario del idioma activo.
import { test, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll, tag } from '../helpers/dom.js';
import { setLang } from '../../src/i18n/index.js';

let dom;
let C;
before(async () => {
  dom = installDom();
  C = {
    ...(await import('../../src/ui/components/mode-switch.js')),
    ...(await import('../../src/ui/components/severity-tag.js')),
    ...(await import('../../src/ui/components/signal-row.js')),
    ...(await import('../../src/ui/components/finding-card.js')),
    ...(await import('../../src/ui/components/verdict-card.js')),
    ...(await import('../../src/ui/components/forensic-dialog.js')),
    ...(await import('../../src/ui/components/rules-panel.js')),
    ...(await import('../../src/ui/components/batch-bar.js')),
    ...(await import('../../src/ui/components/bar-chart.js')),
  };
});
after(() => dom.restore());
afterEach(() => setLang('es'));

const texts = (node) => findAll(node, tag('button')).map((b) => b.textContent);

test('en inglés: conmutador, gravedad, tarjetas y veredicto', () => {
  setLang('en');
  const sw = C.modeSwitch('simple');
  assert.deepEqual(texts(sw), ['Simple', 'Analyst mode']);
  assert.equal(sw.getAttribute('aria-label'), 'Level of detail');
  assert.equal(C.severityTag('high').textContent, 'HIGH');
  assert.equal(find(C.signalRow({ severity: 'low', plain: 'x' }), (n) => n.className === 'signal__sev').textContent, 'Low');
  const card = C.findingCard({ severity: 'medium', points: 15, reliability: 'high', title: 'T', detail: 'D', custom: true });
  assert.match(card.textContent, /high reliability/);
  assert.match(card.textContent, /Custom rule/);
  const v = C.verdictCard({ tone: 'phishing', headline: 'H' }, { score: 95, confidence: { level: 'high' } });
  assert.match(v.textContent, /95 out of 100 · high confidence/);
});

test('en inglés: diálogo forense, reglas, lote y gráficas', () => {
  setLang('en');
  const d = C.forensicDialog({ notes: 'abc' });
  assert.match(d.textContent, /Forensic report/);
  assert.deepEqual(texts(d), ['Save as PDF', 'Download JSON', 'Close']);
  assert.equal(C.notesCount(1234), '1,234 of 5,000');
  assert.match(C.rulesPanel({ state: 'empty' }).textContent, /No custom rules loaded\./);
  assert.match(C.rulesPanel({ state: 'errors', errors: ['a', 'b'] }).textContent, /the file has 2 errors\./);
  const bar = C.batchBar({ items: [{ key: 'a', name: 'n', level: 'phishing', label: 'L', score: 90 }], campaigns: 2, skipped: 1 });
  assert.match(bar.textContent, /1 email · 2 campaigns · 1 dangerous · 1 not analyzed/);
  const chart = C.hBars({ caption: 'c', rows: [{ label: 'x', value: 1 }] });
  assert.match(chart.textContent, /See the data in a table/);
});

test('en español los textos son los de siempre', () => {
  assert.deepEqual(texts(C.modeSwitch('simple')), ['Sencillo', 'Modo analista']);
  assert.equal(C.severityTag('high').textContent, 'GRAVE');
  assert.equal(C.notesCount(1234), '1.234 de 5.000');
  assert.match(C.rulesPanel({ state: 'errors', errors: ['a'] }).textContent, /el fichero tiene 1 error\./);
});
