// Historial (spec 3.0, §2): deduplicado, tope, filtros, búsqueda, comparar, lotes, exportar e importar.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { BATCHES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';
import { createHistory, HISTORY_MAX, IMPORT_MAX_BYTES } from '../../src/storage/history.js';
import { memoryBackend } from '../../src/storage/backends.js';
import * as schema from '../../src/storage/schema.js';

const input = (id) => ({ kind: 'eml', value: SAMPLE_TEXTS[id], name: `${id}.eml`, report: analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id] }) });
function setup(start = Date.parse('2026-11-01T00:00:00.000Z')) {
  let t = start;
  let n = 0;
  const backend = memoryBackend();
  const history = createHistory(backend, {
    now: () => new Date((t += 60000)),
    uuid: () => `00000000-0000-4000-8000-${String(++n).padStart(12, '0')}`,
    version: '2.3.0',
  });
  return { backend, history };
}

test('el mismo correo dos veces es una sola entrada, con la fecha de la segunda', async () => {
  const { history } = setup();
  const a = await history.save(input('03-phishing-banco'));
  const b = await history.save(input('03-phishing-banco'));
  const { items, total } = await history.list();
  assert.equal(total, 1);
  assert.equal(items[0].savedAt, b.entry.savedAt);
  assert.equal(items[0].id, a.entry.id);
  assert.equal(items[0].report.email.text, undefined);
});

test(`tope de ${HISTORY_MAX}: el 501 borra el más antiguo`, async () => {
  const { history } = setup();
  const base = input('01-legitimo-newsletter');
  let last;
  for (let i = 0; i <= HISTORY_MAX; i++) last = await history.save({ ...base, value: `${base.value}\n${i}` });
  assert.equal(last.evicted, 1);
  const { total, items } = await history.list({ limit: 1000 });
  assert.equal(total, HISTORY_MAX);
  assert.ok(!items.some((e) => e.id.endsWith('000000000001')));
});

test('list ordena, pagina y filtra por nivel, fecha y técnica', async () => {
  const { history } = setup();
  for (const id of ['01-legitimo-newsletter', '03-phishing-banco', '13-redireccion-anidada']) await history.save(input(id));
  const all = await history.list();
  assert.deepEqual(all.items.map((e) => e.name), ['13-redireccion-anidada.eml', '03-phishing-banco.eml', '01-legitimo-newsletter.eml']);
  assert.equal((await history.list({ level: 'safe' })).total, 1);
  assert.equal((await history.list({ since: all.items[1].savedAt })).total, 2);
  assert.equal((await history.list({ technique: 'T1566.002' })).items.every((e) => e.report.techniques.some((t) => t.id === 'T1566.002')), true);
  assert.equal((await history.list({ offset: 1, limit: 1 })).items[0].name, '03-phishing-banco.eml');
  const many = setup();
  const base = input('01-legitimo-newsletter');
  for (let i = 0; i < 120; i++) await many.history.save({ ...base, value: `${base.value}\n${i}` });
  const page = await many.history.list();
  assert.equal(page.items.length, 50);
  assert.equal(page.total, 120);
});

test('búsqueda de IOCs y comparar', async () => {
  const { history } = setup();
  const a = (await history.save(input('03-phishing-banco'))).entry;
  const b = (await history.save(input('13-redireccion-anidada'))).entry;
  const hits = await history.searchIoc('SANTANDER');
  assert.ok(hits.some((h) => h.value === 'santander-seguridad.test' && h.type === 'domains' && h.ids.includes(a.id)));
  assert.deepEqual(await history.searchIoc('sa'), []);
  const c = await history.compare(a.id, b.id);
  assert.equal(c.scoreDelta, b.report.score - a.report.score);
  assert.ok(c.onlyA.includes('santander-seguridad.test'));
  assert.ok(!c.onlyB.includes('santander-seguridad.test'));
  assert.ok(Array.isArray(c.findings.shared));
  const lots = setup();
  const base = input('01-legitimo-newsletter');
  for (let i = 0; i < 150; i++) await lots.history.save({ ...base, value: `${base.value}\n${i}`, report: { ...base.report, iocs: { ...base.report.iocs, domains: [`dominio-${i}.test`] } } });
  assert.equal((await lots.history.searchIoc('dominio-')).length, 100);
});

test('un lote guarda una entrada por correo y su registro de campañas', async () => {
  const { history, backend } = setup();
  const entries = BATCHES[0].files.map((f) => ({ kind: 'eml', value: SAMPLE_TEXTS[f], name: f.split('/').pop(), report: analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[f] }) }));
  const out = await history.saveBatch({ entries, campaigns: [{ id: 'c1', name: 'Campaña 1', emails: entries.map((e) => e.name), reasons: [] }] });
  assert.equal(out.saved, 4);
  assert.equal((await history.list()).total, 4);
  const batches = await backend.getAll('batches');
  assert.equal(batches.length, 1);
  assert.equal(batches[0].emails.length, 4);
  assert.ok(batches[0].emails.every((h) => /^[0-9a-f]{64}$/.test(h)));
});

test('exportar e importar da las mismas entradas', async () => {
  const { history } = setup();
  await history.save(input('03-phishing-banco'));
  await history.save(input('13-redireccion-anidada'));
  const json = await history.exportJson();
  assert.equal(JSON.parse(json).phishlens, 'history/1');
  const other = setup();
  const res = await other.history.importJson(json);
  assert.equal(res.imported, 2);
  assert.deepEqual((await other.history.list()).items, (await history.list()).items);
});

test('guardar tarda menos de 20 ms', async () => {
  const { history } = setup();
  const base = input('03-phishing-banco');
  const t0 = performance.now();
  for (let i = 0; i < 50; i++) await history.save({ ...base, value: `${base.value}\n${i}` });
  assert.ok((performance.now() - t0) / 50 < 20);
});

test('Review Focus 2: una entrada manipulada no sale y get da null', async () => {
  const { history, backend } = setup();
  const good = (await history.save(input('03-phishing-banco'))).entry;
  await backend.put('analyses', { ...good, id: '00000000-0000-4000-8000-999999999999', sha256: 'b'.repeat(64), report: { ...good.report, level: 'pwned' } });
  const { total, skipped } = await history.list();
  assert.equal(total, 1);
  assert.equal(skipped, 1);
  assert.equal(await history.get('00000000-0000-4000-8000-999999999999'), null);
  assert.equal(await history.get('no-existe'), null);
});

test('Review Focus 3: vaciado entre list y get no rompe', async () => {
  const { history, backend } = setup();
  await history.save(input('03-phishing-banco'));
  const { items } = await history.list();
  await backend.clear('analyses');
  assert.equal(await history.get(items[0].id), null);
  await history.remove(items[0].id);
  await history.clear();
  assert.equal((await history.list()).total, 0);
});

test('Review Focus 4: importar parcialmente roto, repetidos y demasiado grande', async () => {
  const { history } = setup();
  const saved = (await history.save(input('03-phishing-banco'))).entry;
  const older = { ...saved, id: '00000000-0000-4000-8000-000000000077', savedAt: '2020-01-01T00:00:00.000Z' };
  const other = setup();
  const fresh = (await other.history.save(input('13-redireccion-anidada'))).entry;
  const text = JSON.stringify({ phishlens: 'history/1', entries: [fresh, { ...fresh, kind: 'headers' }, older] });
  const res = await history.importJson(text);
  assert.equal(res.imported, 1);
  assert.equal(res.rejected.length, 1);
  assert.equal(res.rejected[0].index, 1);
  const list = (await history.list()).items;
  assert.equal(list.length, 2);
  assert.equal(list.find((e) => e.sha256 === saved.sha256).savedAt, saved.savedAt);
  await assert.rejects(history.importJson('x'.repeat(IMPORT_MAX_BYTES + 1)), /20 MB/);
  const polluted = await history.importJson('{"__proto__":{"polluted":1},"phishlens":"history/1","entries":[]}');
  assert.equal(polluted.imported, 0);
  assert.equal(({}).polluted, undefined);
  await assert.rejects(history.importJson('{no'), /JSON/);
  assert.ok(typeof schema.safeParse === 'function');
});

test('panel: batches() da los lotes más recientes primero y salta los mal formados', async () => {
  const { history, backend } = setup();
  const a = await history.saveBatch({ entries: [{ ...input('03-phishing-banco'), name: 'a.eml' }], campaigns: [] });
  const b = await history.saveBatch({ entries: [{ ...input('04-phishing-correos'), name: 'b.eml' }], campaigns: [{ id: 'c', name: 'Campaña 1', reasons: ['x'], techniques: [], emails: ['b.eml'] }] });
  await backend.put('batches', { id: 'roto', savedAt: '2026-12-01T00:00:00.000Z', emails: [], campaigns: 'x' });
  const list = await history.batches();
  assert.deepEqual(list.map((x) => x.id), [b.id, a.id]);
  assert.equal(list[0].campaigns[0].emails.length, 1);
  assert.equal((await history.batches({ limit: 1 })).length, 1);
});

test('panel: findBySha256() devuelve la entrada validada o null', async () => {
  const { history } = setup();
  const { entry } = await history.save(input('03-phishing-banco'));
  assert.equal((await history.findBySha256(entry.sha256)).id, entry.id);
  assert.equal(await history.findBySha256('f'.repeat(64)), null);
  assert.equal(await history.findBySha256('no es un hash'), null);
});
