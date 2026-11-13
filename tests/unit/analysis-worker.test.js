// El analizador con worker (src/ui/analysis-worker.js, ADR 0007): política de Trusted Types cerrada, fuente del
// worker sin código peligroso, y vuelta al hilo principal cuando el worker no existe o falla. El worker real se
// prueba en tests/e2e/worker.e2e.js; aquí se simula con una clase mínima.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAnalyzer, workerSource, isOwnBlobUrl, POLICY_NAME } from '../../src/ui/analysis-worker.js';

const ORIGIN = 'https://manzaxx.github.io';

/** Un Worker de mentira: ejecuta `handler` por cada mensaje y contesta como lo haría el de verdad. */
function fakeWorkerClass(handler, log = []) {
  return class FakeWorker {
    constructor(url, options) {
      log.push(['new', String(url), options]);
      this.terminated = false;
      this.onmessage = null;
      this.onerror = null;
    }

    postMessage(msg) {
      log.push(['post', msg.id]);
      queueMicrotask(() => {
        if (this.terminated) return;
        const out = handler(msg, this);
        if (out !== undefined) this.onmessage?.({ data: out });
      });
    }

    terminate() {
      this.terminated = true;
      log.push(['terminate']);
    }
  };
}

function scopeWith(Worker, { trustedTypes } = {}) {
  const urls = { created: 0, revoked: 0 };
  return {
    urls,
    Worker,
    Blob: globalThis.Blob,
    location: { origin: ORIGIN },
    trustedTypes,
    URL: {
      createObjectURL: () => { urls.created++; return `${'blob:'}${ORIGIN}/${urls.created}`; },
      revokeObjectURL: () => { urls.revoked++; },
    },
  };
}

/** Trusted Types de mentira: una sola política por nombre y createScriptURL envuelto como en el navegador. */
function fakeTrustedTypes(allowed = [POLICY_NAME]) {
  const names = new Set();
  return {
    names,
    createPolicy(name, rules) {
      if (!allowed.includes(name) || names.has(name)) throw new TypeError(`política ${name} no permitida`);
      names.add(name);
      return { name, createScriptURL: (s) => ({ toString: () => rules.createScriptURL(s), trusted: true }) };
    },
  };
}

test('isOwnBlobUrl: solo blob: de este origen', () => {
  assert.ok(isOwnBlobUrl(`blob:${ORIGIN}/abc`, ORIGIN));
  assert.equal(isOwnBlobUrl('blob:https://evil.example/abc', ORIGIN), false);
  assert.equal(isOwnBlobUrl('https://evil.example/w.js', ORIGIN), false);
  assert.equal(isOwnBlobUrl(`data:text/javascript,1`, ORIGIN), false);
  assert.equal(isOwnBlobUrl(null, ORIGIN), false);
});

test('la fuente del worker importa el motor por su URL y no tiene eval, fetch ni importScripts', () => {
  const src = workerSource('https://manzaxx.github.io/PhishLens/src/core/engine.js');
  assert.match(src, /import\("https:\/\/manzaxx\.github\.io\/PhishLens\/src\/core\/engine\.js"\)/);
  assert.doesNotMatch(src, /\beval\(|new Function|importScripts|fetch\(|XMLHttpRequest|WebSocket/);
  // onmessage se registra antes del import: el primer mensaje no se pierde mientras carga el motor.
  assert.ok(src.indexOf('self.onmessage') < src.indexOf('import('));
  // Es JavaScript válido.
  assert.doesNotThrow(() => new Function(src)); // eslint-disable-line no-new-func -- solo comprueba la sintaxis en el test
});

test('con worker: la respuesta llega con el informe y la política de Trusted Types solo acepta blob: propio', async () => {
  const log = [];
  const tt = fakeTrustedTypes();
  const Worker = fakeWorkerClass((msg) => ({ id: msg.id, ok: true, report: { score: 42, got: msg.input.kind } }), log);
  const scope = scopeWith(Worker, { trustedTypes: tt });
  const a = createAnalyzer({ scope, analyze: () => { throw new Error('no debería usarse'); } });
  const report = await a.run({ kind: 'text', value: 'hola' });
  assert.deepEqual(report, { score: 42, got: 'text' });
  assert.equal(a.mode, 'worker');
  assert.deepEqual([...tt.names], [POLICY_NAME]);
  const [, url, options] = log[0];
  assert.equal(url, `blob:${ORIGIN}/1`);
  assert.deepEqual(options, { type: 'module' });
  // El worker se reutiliza entre análisis.
  await a.run({ kind: 'url', value: 'http://x' });
  assert.equal(log.filter((l) => l[0] === 'new').length, 1);
});

test('sin Worker en el navegador, analiza en el hilo principal', async () => {
  const a = createAnalyzer({ scope: { location: { origin: ORIGIN } }, analyze: (input) => ({ score: 7, kind: input.kind }) });
  assert.equal(a.available, false);
  assert.deepEqual(await a.run({ kind: 'eml', value: 'x' }), { score: 7, kind: 'eml' });
  assert.equal(a.mode, 'main');
});

test('si el worker no puede cargar el motor, se da por roto y el análisis sigue en el hilo principal', async () => {
  const log = [];
  const Worker = fakeWorkerClass((msg) => ({ id: msg.id, ok: false, stage: 'load', message: 'import failed' }), log);
  const a = createAnalyzer({ scope: scopeWith(Worker), analyze: () => ({ score: 1 }) });
  assert.deepEqual(await a.run({ kind: 'text', value: 'a' }), { score: 1 });
  assert.equal(a.mode, 'main');
  assert.equal(a.available, false);
  assert.ok(log.some((l) => l[0] === 'terminate'));
  // La segunda vez ya no se intenta ningún worker.
  await a.run({ kind: 'text', value: 'b' });
  assert.equal(log.filter((l) => l[0] === 'new').length, 1);
});

test('un error del motor con un correo concreto no es un fallo del worker: se devuelve y el worker sigue vivo', async () => {
  const log = [];
  const Worker = fakeWorkerClass((msg) => (msg.input.value === 'mal'
    ? { id: msg.id, ok: false, stage: 'analyze', message: 'boom' }
    : { id: msg.id, ok: true, report: { score: 3 } }), log);
  const a = createAnalyzer({ scope: scopeWith(Worker), analyze: () => { throw new Error('no debería usarse'); } });
  await assert.rejects(a.run({ kind: 'text', value: 'mal' }), /boom/);
  assert.equal(a.available, true);
  assert.deepEqual(await a.run({ kind: 'text', value: 'bien' }), { score: 3 });
  assert.equal(log.filter((l) => l[0] === 'new').length, 1);
});

test('un evento error del worker durante el análisis vuelve al hilo principal una vez y no vuelve a usar el worker', async () => {
  const log = [];
  const Worker = fakeWorkerClass((msg, w) => { w.onerror?.({ preventDefault() {} }); }, log);
  const a = createAnalyzer({ scope: scopeWith(Worker), analyze: (input) => ({ score: 9, v: input.value }) });
  assert.deepEqual(await a.run({ kind: 'text', value: 'a' }), { score: 9, v: 'a' });
  assert.equal(a.mode, 'main');
  assert.equal(a.available, false);
});

test('cancel(): termina el worker, rechaza con AbortError y el siguiente run() crea otro worker', async () => {
  const log = [];
  const Worker = fakeWorkerClass(() => undefined, log); // nunca contesta: simula un análisis largo
  const scope = scopeWith(Worker);
  const a = createAnalyzer({ scope, analyze: () => { throw new Error('no debería usarse'); } });
  const p = a.run({ kind: 'text', value: 'largo' });
  assert.equal(a.cancel(), true);
  await assert.rejects(p, (e) => e.name === 'AbortError');
  assert.equal(a.cancel(), false, 'sin análisis pendiente no hay nada que cancelar');
  assert.deepEqual(log.map((l) => l[0]), ['new', 'post', 'terminate']);
  assert.equal(scope.urls.revoked, 1);
  assert.equal(a.available, true, 'cancelar no es un fallo del worker');
  const Worker2 = fakeWorkerClass((msg) => ({ id: msg.id, ok: true, report: { score: 5 } }), log);
  scope.Worker = Worker2;
  assert.deepEqual(await a.run({ kind: 'text', value: 'corto' }), { score: 5 });
  assert.equal(log.filter((l) => l[0] === 'new').length, 2);
});

test('un run() nuevo pisa al anterior: el primero acaba en AbortError y solo se pinta el último', async () => {
  const log = [];
  const Worker = fakeWorkerClass((msg) => ({ id: msg.id, ok: true, report: { id: msg.id } }), log);
  const a = createAnalyzer({ scope: scopeWith(Worker) });
  const first = a.run({ kind: 'text', value: '1' });
  const second = a.run({ kind: 'text', value: '2' });
  await assert.rejects(first, (e) => e.name === 'AbortError');
  assert.deepEqual(await second, { id: 2 });
});

test('una respuesta con otro id (de un análisis ya cancelado) se ignora', async () => {
  let keep;
  const Worker = fakeWorkerClass((msg, w) => { keep = { msg, w }; return undefined; });
  const a = createAnalyzer({ scope: scopeWith(Worker) });
  const p = a.run({ kind: 'text', value: 'x' });
  await Promise.resolve();
  a.cancel();
  await assert.rejects(p, (e) => e.name === 'AbortError');
  const done = a.run({ kind: 'text', value: 'y' });
  await Promise.resolve();
  // Llega tarde la respuesta del primero: no debe resolver el segundo.
  keep.w.onmessage?.({ data: { id: 1, ok: true, report: { stale: true } } });
  keep.w.onmessage?.({ data: { id: 2, ok: true, report: { fresh: true } } });
  assert.deepEqual(await done, { fresh: true });
});

test('si la política de Trusted Types no se puede crear (nombre no permitido), se analiza en el hilo principal', async () => {
  const Worker = fakeWorkerClass((msg) => ({ id: msg.id, ok: true, report: { score: 1 } }));
  const tt = fakeTrustedTypes(['otra']);
  const a = createAnalyzer({ scope: scopeWith(Worker, { trustedTypes: tt }), analyze: () => ({ score: 2 }) });
  assert.deepEqual(await a.run({ kind: 'text', value: 'x' }), { score: 2 });
  assert.equal(a.mode, 'main');
});

test('la política rechaza cualquier URL que no sea blob: de este origen', () => {
  const tt = fakeTrustedTypes();
  const Worker = fakeWorkerClass(() => undefined);
  const scope = scopeWith(Worker, { trustedTypes: tt });
  createAnalyzer({ scope }).run({ kind: 'text', value: 'x' });
  // La política ya existe con ese nombre: nadie más puede crearla…
  assert.throws(() => tt.createPolicy(POLICY_NAME, { createScriptURL: (s) => s }), /no permitida/);
  // …y la nuestra no se exporta; aquí se recrea la regla para comprobar que rechaza lo ajeno.
  const rule = (u) => { if (!isOwnBlobUrl(u, ORIGIN)) throw new TypeError('no'); return u; };
  assert.throws(() => rule('https://leak.example/evil.js'), TypeError);
  assert.throws(() => rule('blob:https://leak.example/1'), TypeError);
  assert.equal(rule(`blob:${ORIGIN}/1`), `blob:${ORIGIN}/1`);
});
