// Informe forense en pantalla e impreso (spec 3.0, §4): secciones en orden, tablas con cabecera, gravedad
// en texto, notas como texto y el diálogo con las dos salidas.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll } from '../helpers/dom.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeInput } from '../../src/core/engine.js';
import { forensicReport } from '../../src/intel/forensic.js';

let dom;
let renderForensic;
let forensicDialog;
before(async () => {
  dom = installDom();
  ({ renderForensic } = await import('../../src/ui/views/forensic.js'));
  ({ forensicDialog } = await import('../../src/ui/components/forensic-dialog.js'));
});
after(() => dom.restore());

const local = (n) => n.localName ?? n.tagName?.toLowerCase();
const attr = (n, k) => n.getAttribute?.(k) ?? null;
const cls = (n) => attr(n, 'class') ?? '';
const doc = (id, notes = '') => {
  const text = SAMPLE_TEXTS[id];
  return forensicReport({ report: analyzeInput({ kind: 'eml', value: text }), source: { kind: 'live', name: `${id}.eml`, text }, analyzedAt: new Date('2026-11-10T12:00:00Z'), version: '2.3.0', notes });
};
const ORDER = ['Identificación', 'Veredicto', 'Hallazgos', 'Autenticación', 'Cronología', 'IOCs', 'Adjuntos', 'URLs', 'Notas del analista', 'Límites'];

test('renderForensic: diez secciones en orden con su h2, y la pista de «Guardar como PDF»', () => {
  const root = renderForensic(doc('12-pdf-activo-zip', 'Revisado con el equipo.'));
  assert.ok(cls(root).split(' ').includes('forensic'));
  assert.deepEqual(findAll(root, (n) => local(n) === 'h2').map((n) => n.textContent), ORDER);
  assert.match(find(root, (n) => local(n) === 'h1').textContent, /Informe forense/);
  assert.match(root.textContent, /«Guardar como PDF»/);
});

test('sin notas no hay sección de notas, pero sí las otras nueve', () => {
  const root = renderForensic(doc('03-phishing-banco'));
  assert.deepEqual(findAll(root, (n) => local(n) === 'h2').map((n) => n.textContent), ORDER.filter((t) => t !== 'Notas del analista'));
});

test('tablas con thead y la gravedad en texto', () => {
  const root = renderForensic(doc('12-pdf-activo-zip'));
  const tables = findAll(root, (n) => local(n) === 'table');
  assert.ok(tables.length >= 4);
  for (const t of tables) assert.ok(find(t, (n) => local(n) === 'thead'), 'cada tabla con cabecera');
  const sev = findAll(root, (n) => cls(n).split(' ').includes('sev')).map((n) => n.textContent);
  assert.ok(sev.includes('GRAVE'), sev.join(','));
});

test('Review Focus 2: notas con <script> y RLO salen como texto revelado, sin <script> en el árbol', () => {
  const root = renderForensic(doc('03-phishing-banco', '<script>alert(1)</script>\u202Eabc'));
  assert.equal(findAll(root, (n) => local(n) === 'script').length, 0);
  const notes = find(root, (n) => cls(n).includes('forensic__notes'));
  assert.ok(notes.textContent.startsWith('<script>alert(1)</script>'));
  assert.match(notes.textContent, /⟦U\+202E⟧/);
});

test('pie con el SHA-256 del texto analizado; desde el historial, lo que no hay dice «No disponible»', () => {
  const d = doc('03-phishing-banco');
  assert.equal(find(renderForensic(d), (n) => cls(n).includes('forensic__footer')).textContent, `SHA-256 ${d.identification.sha256}`);
  const saved = forensicReport({ report: analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS['03-phishing-banco'] }), source: { kind: 'saved', name: null, sha256: 'b'.repeat(64), savedAt: '2026-11-01T10:00:00.000Z' }, analyzedAt: new Date('2026-11-01T10:00:00Z'), version: '2.3.0' });
  const text = renderForensic(saved).textContent;
  assert.match(text, /No disponible: el correo no se guarda/);
  assert.match(text, /Guardado en el historial/);
});

test('forensicDialog: textarea con maxlength 5000 y su contador, dos acciones, Cerrar y la pista', () => {
  const dlg = forensicDialog({ notes: 'hola' });
  assert.equal(local(dlg), 'dialog');
  assert.ok(attr(dlg, 'aria-labelledby'));
  const ta = find(dlg, (n) => local(n) === 'textarea');
  assert.equal(attr(ta, 'maxlength'), '5000');
  assert.equal(attr(ta, 'data-role'), 'forensic-notes');
  assert.equal(ta.value ?? ta.textContent, 'hola');
  const label = find(dlg, (n) => local(n) === 'label');
  assert.equal(attr(label, 'for'), attr(ta, 'id'));
  assert.equal(find(dlg, (n) => attr(n, 'data-role') === 'forensic-count').textContent, '4 de 5.000');
  const actions = findAll(dlg, (n) => local(n) === 'button').map((b) => [attr(b, 'data-action'), b.textContent]);
  assert.deepEqual(actions, [['forensic-print', 'Guardar como PDF'], ['forensic-json', 'Descargar JSON'], ['forensic-close', 'Cerrar']]);
  assert.match(dlg.textContent, /En el diálogo de impresión, elige «Guardar como PDF» como destino\./);
});

test('revisión final: las notas guardadas vuelven al campo tal cual, sin revelar el RLO', () => {
  const raw = 'a\u202Eb';
  const ta = find(forensicDialog({ notes: raw }), (n) => attr(n, 'data-role') === 'forensic-notes');
  assert.equal(ta.value, raw);
  assert.ok(!String(ta.textContent ?? '').includes('⟦'));
});

test('revisión final: si el historial está activado y las notas no se guardan, se dice', async () => {
  const { notesSaveMessage } = await import('../../src/ui/components/forensic-dialog.js');
  assert.equal(notesSaveMessage({ enabled: false, ok: false }), null);
  assert.equal(notesSaveMessage({ enabled: true, ok: true }), null);
  assert.match(notesSaveMessage({ enabled: true, ok: false }), /No se han podido guardar las notas/);
});

test('PR13: un hallazgo de regla propia lleva «(regla propia)» en el informe y custom en el JSON', async () => {
  const { validateRules } = await import('../../src/rules/validate.js');
  const { rules } = validateRules(JSON.stringify({ phishlens: 'rules/1', rules: [{ id: 'prueba', title: 'Mi regla', severity: 'high', category: 'sender', when: { field: 'subject', op: 'exists' } }] }));
  const text = SAMPLE_TEXTS['03-phishing-banco'];
  const d = forensicReport({ report: analyzeInput({ kind: 'eml', value: text, rules }), source: { kind: 'live', name: null, text }, analyzedAt: new Date('2026-11-10T12:00:00Z'), version: '3.0.0', notes: '' });
  const f = d.findings.find((x) => x.id === 'custom.prueba');
  assert.equal(f.custom, true);
  assert.equal(d.findings.find((x) => x.id !== 'custom.prueba').custom, false);
  const root = renderForensic(d);
  assert.ok(findAll(root, (n) => n.textContent === 'Mi regla (regla propia)').length > 0);
});
