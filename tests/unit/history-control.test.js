// Interruptor del historial (spec 3.0, §2.1 y §2.4): apagado no guarda, encendido guarda, y un fallo
// de IndexedDB nunca rompe el análisis.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { BATCHES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';
import { createHistoryControl } from '../../src/ui/history-control.js';
import { memoryBackend } from '../../src/storage/backends.js';

function storage(initial = {}) {
  const map = new Map(Object.entries(initial));
  return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => map.set(k, String(v)), map };
}
const input = (id, extra = {}) => ({ kind: 'eml', value: SAMPLE_TEXTS[id], ...extra });
function control(opts = {}) {
  const backend = opts.backend ?? memoryBackend();
  let opened = 0;
  const ctl = createHistoryControl({
    storage: opts.storage ?? storage(), version: '2.3.0',
    open: opts.open ?? (async () => { opened++; return backend; }),
  });
  return { ctl, backend, opened: () => opened };
}

test('apagado no abre la base ni guarda', async () => {
  const { ctl, opened, backend } = control();
  assert.equal(ctl.enabled(), false);
  await ctl.record(input('03-phishing-banco'), analyzeInput(input('03-phishing-banco')), 'x.eml');
  assert.equal(opened(), 0);
  assert.equal(await backend.count('analyses'), 0);
  assert.equal(ctl.history(), null);
});

test('encendido guarda y recuerda el estado', async () => {
  const s = storage();
  const { ctl, backend } = control({ storage: s });
  assert.deepEqual(await ctl.enable(), { ok: true });
  assert.equal(s.map.get('phishlens-history'), 'on');
  await ctl.record(input('03-phishing-banco'), analyzeInput(input('03-phishing-banco')), 'x.eml');
  assert.equal(await backend.count('analyses'), 1);
  ctl.disable();
  assert.equal(s.map.get('phishlens-history'), 'off');
  assert.equal(ctl.enabled(), false);
  assert.equal(await backend.count('analyses'), 1, 'apagar no borra');
});

test('al cargar con «on» guardado, ready() abre la base', async () => {
  const { ctl, opened } = control({ storage: storage({ 'phishlens-history': 'on' }) });
  await ctl.ready();
  assert.equal(ctl.enabled(), true);
  assert.equal(opened(), 1);
});

test('Review Focus 5: volver a analizar el mismo texto actualiza su entrada', async () => {
  const { ctl, backend } = control();
  await ctl.enable();
  const a = input('03-phishing-banco');
  await ctl.record(a, analyzeInput(a), 'x.eml');
  const b = input('03-phishing-banco', { spfRecord: 'v=spf1 ip4:198.51.100.23 -all' });
  await ctl.record(b, analyzeInput(b), 'x.eml');
  assert.equal(await backend.count('analyses'), 1);
  const entries = BATCHES[0].files.map((f) => ({ key: f, name: f.split('/').pop(), report: analyzeInput(input(f)) }));
  await ctl.recordBatch({ entries, campaigns: [] }, new Map(BATCHES[0].files.map((f) => [f, SAMPLE_TEXTS[f]])));
  assert.equal(await backend.count('analyses'), 5);
  assert.equal((await backend.getAll('batches')).length, 1);
});

test('Review Focus 1: si IndexedDB falla al guardar, el análisis sigue y el historial se apaga', async () => {
  const backend = memoryBackend();
  backend.put = async () => { const e = new Error('lleno'); e.name = 'QuotaExceededError'; throw e; };
  const { ctl } = control({ backend });
  const events = [];
  ctl.on('unavailable', () => events.push('unavailable'));
  await ctl.enable();
  await assert.doesNotReject(ctl.record(input('03-phishing-banco'), analyzeInput(input('03-phishing-banco'))));
  assert.equal(ctl.enabled(), false);
  assert.deepEqual(events, ['unavailable']);
  const broken = control({ open: async () => { throw new Error('IndexedDB no está disponible'); } });
  assert.deepEqual(await broken.ctl.enable(), { ok: false, reason: 'unavailable' });
  assert.equal(broken.ctl.enabled(), false);
});

test('avisa cuando borra el más antiguo', async () => {
  const { ctl } = control();
  const events = [];
  ctl.on('evicted', (n) => events.push(n));
  await ctl.enable();
  const base = input('01-legitimo-newsletter');
  const report = analyzeInput(base);
  for (let i = 0; i <= 500; i++) await ctl.record({ ...base, value: `${base.value}\n${i}` }, report);
  assert.deepEqual(events, [1]);
});

test('«Borrar todo» deja la base cerrada y borrada; el siguiente análisis la vuelve a abrir', async () => {
  let destroyed = 0;
  const backend = memoryBackend();
  const destroy = backend.destroy;
  backend.destroy = async () => { destroyed++; return destroy(); };
  const { ctl, opened } = control({ backend });
  await ctl.enable();
  await ctl.record(input('03-phishing-banco'), analyzeInput(input('03-phishing-banco')), 'x.eml');
  await ctl.clear();
  assert.equal(destroyed, 1);
  assert.equal(ctl.history(), null, 'sin conexión abierta tras borrar');
  assert.equal(ctl.enabled(), true, 'el interruptor sigue encendido');
  assert.equal(opened(), 1);
  await ctl.record(input('04-phishing-correos'), analyzeInput(input('04-phishing-correos')), 'y.eml');
  assert.equal(opened(), 2);
  assert.equal((await ctl.history().list()).total, 1);
});

test('revisión final: si otra pestaña borró la base, se reconecta una vez y guarda sin apagar el historial', async () => {
  const good = memoryBackend();
  let calls = 0;
  const closed = { ...memoryBackend(), getByIndex: async () => { throw new Error('el historial está cerrado'); } };
  const { ctl } = control({ open: async () => (calls++ === 0 ? closed : good) });
  await ctl.enable();
  let off = false;
  ctl.on('unavailable', () => { off = true; });
  await ctl.record(input('03-phishing-banco'), analyzeInput(input('03-phishing-banco')), 'x.eml');
  assert.equal(off, false);
  assert.equal(ctl.enabled(), true);
  assert.equal(await good.count('analyses'), 1);
});

test('revisión final: ensure() reabre la base tras «Borrar todo» para poder importar', async () => {
  const { ctl } = control();
  await ctl.enable();
  await ctl.clear();
  assert.equal(ctl.history(), null);
  assert.equal(await ctl.ensure(), true);
  assert.ok(ctl.history());
  ctl.disable();
  assert.equal(await ctl.ensure(), false, 'apagado no abre nada');
  assert.equal(ctl.history(), null);
});
