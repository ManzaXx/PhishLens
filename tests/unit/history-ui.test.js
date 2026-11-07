// Vista «Historial» (spec 3.0, §2.3): tabla paginada, búsqueda, filtros, comparar y borrar, sin HTML.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll, tag } from '../helpers/dom.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeInput } from '../../src/core/engine.js';
import { slimReport } from '../../src/storage/schema.js';

let dom;
let historyPanel;
before(async () => {
  dom = installDom();
  ({ historyPanel } = await import('../../src/ui/panels/history.js'));
});
after(() => dom.restore());

const r03 = slimReport(analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS['03-phishing-banco'] }));
const entry = (i, report = r03) => ({
  id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`, savedAt: new Date(Date.UTC(2026, 10, 1, 0, i)).toISOString(),
  version: '2.3.0', kind: 'eml', sha256: 'a'.repeat(64), name: `correo-${i}.eml`, report,
});
const data = (over = {}) => ({ page: { items: [], total: 0, skipped: 0, offset: 0 }, filters: {}, techniques: [], search: null, compare: null, selected: [], importResult: null, ...over });
const text = (n) => n.textContent;
const attr = (n, k) => n.getAttribute?.(k) ?? null;

test('120 entradas: 50 filas, rango y paginación; nada es un enlace y todo va defanged', () => {
  const items = Array.from({ length: 50 }, (_, i) => entry(i));
  const panel = historyPanel(r03, { history: data({ page: { items, total: 120, skipped: 0, offset: 0 } }) });
  assert.equal(findAll(panel, (n) => n.localName === 'tr' && n.parentNode?.localName === 'tbody').length, 50);
  assert.match(text(panel), /Se muestran 1–50 de 120/);
  assert.equal(findAll(panel, tag('a')).length, 0);
  assert.ok(!text(panel).includes('santander-seguridad.test'), 'remitente defanged');
  assert.ok(find(panel, (n) => attr(n, 'data-action') === 'history-page' && attr(n, 'data-offset') === '50'));
  assert.ok(findAll(panel, (n) => attr(n, 'data-action') === 'history-open').length === 50);
  assert.ok(findAll(panel, (n) => attr(n, 'data-action') === 'history-delete').length === 50);
});

test('un asunto con HTML sale como texto', () => {
  const evil = { ...r03, email: { ...r03.email, subject: '<img src=x onerror=alert(1)>' } };
  const panel = historyPanel(r03, { history: data({ page: { items: [entry(1, evil)], total: 1, skipped: 0, offset: 0 } }) });
  assert.equal(findAll(panel, tag('img')).length, 0);
  assert.match(text(panel), /<img src=x onerror=alert\(1\)>/);
});

test('aviso de entradas saltadas, diálogo de borrar con su número y estado vacío', () => {
  const panel = historyPanel(r03, { history: data({ page: { items: [entry(1)], total: 3, skipped: 2, offset: 0 } }) });
  assert.match(text(panel), /2 entradas guardadas no se han podido leer y se han saltado\./);
  const dialog = find(panel, tag('dialog'));
  assert.match(text(dialog), /¿Borrar los 3 análisis guardados\? No se puede deshacer\./);
  assert.ok(findAll(dialog, tag('button')).some((b) => text(b) === 'Borrar 3 análisis'));
  assert.ok(findAll(dialog, tag('button')).some((b) => text(b) === 'Cancelar'));
  const empty = historyPanel(r03, { history: data() });
  assert.match(text(empty), /Aún no hay nada guardado\.\s*Activa el historial y analiza algún correo para verlo aquí\./);
});

test('búsqueda, filtros, comparación y resultado de importar', () => {
  const panel = historyPanel(r03, { history: data({
    page: { items: [entry(1), entry(2)], total: 2, skipped: 0, offset: 0 },
    techniques: ['T1566.002'],
    search: { query: 'santander', results: [{ value: 'santander-seguridad.test', type: 'domains', ids: ['x', 'y'] }] },
    compare: { a: entry(1), b: entry(2), sharedIocs: ['santander-seguridad.test'], onlyA: [], onlyB: ['x.test'], scoreDelta: -20, findings: { shared: ['links.x'], onlyA: [], onlyB: [] } },
    importResult: { imported: 3, rejected: [{ index: 1, error: 'kind: debe ser eml, text o url' }] },
  }) });
  assert.match(text(panel), /santander-seguridad\[\.\]test/);
  assert.match(text(panel), /aparece en 2 análisis/);
  assert.ok(find(panel, (n) => n.localName === 'input' && n.getAttribute('type') === 'search'));
  assert.equal(findAll(panel, (n) => n.localName === 'select').length, 3);
  assert.match(text(panel), /Diferencia de puntuación: −20/);
  assert.match(text(panel), /Importados 3; rechazados 1/);
  assert.match(text(panel), /Entrada 2: kind: debe ser eml, text o url/);
  for (const s of findAll(panel, (n) => n.localName === 'select' || (n.localName === 'input' && n.getAttribute('type') === 'search'))) {
    const id = s.getAttribute('id');
    assert.ok(find(panel, (n) => n.localName === 'label' && n.getAttribute('for') === id), `etiqueta de ${id}`);
  }
});
