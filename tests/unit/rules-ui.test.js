// «Reglas propias» en la portada (spec 3.0, §5.2): estados del panel, errores, vista previa y texto seguro.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installDom, find, findAll } from '../helpers/dom.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeInput } from '../../src/core/engine.js';
import { validateRules, formatRuleError } from '../../src/rules/validate.js';
import { previewRules } from '../../src/rules/preview.js';

let dom;
let rulesPanel;
before(async () => {
  dom = installDom();
  ({ rulesPanel } = await import('../../src/ui/components/rules-panel.js'));
});
after(() => dom.restore());

const EXAMPLE = readFileSync(new URL('../../samples/rules/ejemplo.json', import.meta.url), 'utf8');
const { rules } = validateRules(EXAMPLE);
const entry = (id) => ({ report: analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id] }) });
const attr = (n, k) => n.getAttribute?.(k) ?? null;
const texts = (root) => findAll(root, () => true).map((n) => n.textContent);

test('previewRules: solo prueba las reglas que usan únicamente finding.id, con N de M análisis', () => {
  const extra = validateRules(JSON.stringify({ phishlens: 'rules/1', rules: [{ id: 'solo-hallazgos', title: 'Solo hallazgos', severity: 'low', category: 'sender', when: { any: [{ field: 'finding.id', op: 'starts-with', value: 'lookalike.' }, { not: { field: 'finding.id', op: 'exists' } }] } }] })).rules;
  const entries = ['03-phishing-banco', '04-phishing-correos', '02-legitimo-pedido'].map(entry);
  const p = previewRules([...rules, ...extra], entries);
  // La regla 3 mira también link.url, que no se guarda: no se puede probar. La 02 no tiene hallazgos: cumple el «not exists».
  assert.deepEqual(p.map((x) => [x.id, x.testable, x.matches, x.total]), [
    ['mi-org.factura-falsa', false, 0, 3],
    ['mi-org.ejecutable-o-imagen', false, 0, 3],
    ['mi-org.suplantacion-con-enlace', false, 0, 3],
    ['solo-hallazgos', true, 3, 3],
  ]);
});

test('previewRules: entradas manipuladas o sin hallazgos no lanzan', () => {
  const p = previewRules(rules, [{}, { report: null }, { report: { findings: 'x' } }, { report: { findings: [null, { id: 3 }] } }]);
  assert.equal(p[2].matches, 0);
  assert.equal(p[2].total, 4);
});

test('panel vacío: solo el texto de que no hay reglas', () => {
  const root = rulesPanel({ state: 'empty' });
  assert.ok(texts(root).some((t) => t === 'No hay reglas propias cargadas.'));
  assert.equal(find(root, (n) => attr(n, 'data-action') === 'rules-activate'), null);
});

test('panel con errores: role="alert" con cada error en el formato de formatRuleError', () => {
  const bad = validateRules(EXAMPLE.replace('"op": "contains"', '"op": "matches"'));
  const root = rulesPanel({ state: 'errors', errors: bad.errors.map(formatRuleError) });
  const alert = find(root, (n) => attr(n, 'role') === 'alert');
  assert.ok(alert);
  assert.match(alert.textContent, /No se han cargado las reglas: el fichero tiene 1 error\./);
  assert.ok(texts(alert).includes('Regla 1, `when.all[0].op`: «matches» no es un operador admitido'));
});

test('vista previa: tabla con cada regla y «Activar reglas»; activas: «N reglas activas» y «Quitar reglas»', () => {
  const preview = previewRules(rules, [entry('03-phishing-banco')]);
  const p = rulesPanel({ state: 'preview', rules, preview });
  assert.ok(find(p, (n) => attr(n, 'data-action') === 'rules-activate'));
  assert.ok(find(p, (n) => attr(n, 'data-action') === 'rules-discard'));
  const all = texts(p);
  assert.ok(all.includes('No se puede probar con el historial: necesita el correo, y el correo no se guarda'));
  const testable = validateRules(JSON.stringify({ phishlens: 'rules/1', rules: [{ id: 'solo-hallazgos', title: 'S', severity: 'low', category: 'sender', when: { field: 'finding.id', op: 'starts-with', value: 'lookalike.' } }] })).rules;
  assert.ok(texts(rulesPanel({ state: 'preview', rules: testable, preview: previewRules(testable, [entry('03-phishing-banco')]) })).includes('Cumpliría en 1 de 1 análisis guardados'));
  const a = rulesPanel({ state: 'active', rules, preview: previewRules(rules, []) });
  assert.ok(texts(a).includes('3 reglas activas'));
  assert.ok(texts(rulesPanel({ state: 'active', rules: testable, preview: previewRules(testable, []) })).includes('Sin análisis guardados para probarla'));
  assert.ok(find(a, (n) => attr(n, 'data-action') === 'rules-remove'));
  assert.ok(texts(rulesPanel({ state: 'active', rules: rules.slice(0, 1), preview: [] })).includes('1 regla activa'));
});

test('título con <script> y RLO sale como texto revelado', () => {
  const { rules: hostile } = validateRules(JSON.stringify({ phishlens: 'rules/1', rules: [{ id: 'mala', title: '<script>x</script>\u202Eabc', severity: 'low', category: 'sender', when: { field: 'subject', op: 'exists' } }] }));
  const root = rulesPanel({ state: 'preview', rules: hostile, preview: previewRules(hostile, []) });
  assert.equal(findAll(root, (n) => (n.localName ?? n.tagName?.toLowerCase()) === 'script').length, 0);
  assert.ok(texts(root).some((t) => t.startsWith('<script>x</script>⟦U+202E⟧')));
});
