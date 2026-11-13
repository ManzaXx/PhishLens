// Análisis en un Web Worker (auditoría 3.1, P5; ADR 0007). El worker nace de un `blob:` con un module script de
// unas líneas que importa el motor por su URL del mismo origen. Un worker creado desde `blob:` hereda la CSP del
// documento que lo crea (CSP3, «inheriting the policy of the owner document»; comprobado en
// tests/e2e/worker.e2e.js con una prueba que intenta fetch, XHR, WebSocket, import remoto y eval desde dentro):
// dentro siguen valiendo connect-src 'none' y script-src 'self', así que el worker no puede hablar con nadie.
//
// Trusted Types: la CSP solo admite la política `phishlens-worker`, que únicamente acepta un `blob:` de este
// origen. La política vive en este módulo y no se expone: ni un script inyectado podría crear otra con ese nombre
// (sin 'allow-duplicates' el segundo createPolicy lanza) ni pasar una URL remota por esta.
//
// Si el navegador no tiene Worker, la política no se puede crear o el worker falla al arrancar, el análisis vuelve
// al hilo principal, que es lo que hacía la web hasta la 3.1. Un error del motor con un correo concreto no es un
// fallo del worker: se devuelve tal cual para que la interfaz enseñe el mismo aviso de siempre.
import { analyzeInput } from '../core/engine.js';

export const POLICY_NAME = 'phishlens-worker';
const ENGINE_URL = new URL('../core/engine.js', import.meta.url).href;

/** Solo un `blob:` de este mismo origen puede ser el script del worker. */
export const isOwnBlobUrl = (url, origin) => typeof url === 'string' && url.startsWith(`blob:${origin}/`);

/**
 * Fuente del worker. Sin eval, sin código remoto: importa el motor con import() (un import estático en un module
 * worker blob: falla sin mensaje en Chromium) y contesta a cada mensaje con su mismo id.
 * Se registra onmessage antes de importar nada: un mensaje que llegue durante la carga no se pierde.
 */
export function workerSource(engineUrl = ENGINE_URL) {
  return [
    'let engine = null;',
    'self.onmessage = async (e) => {',
    '  const { id, input } = e.data;',
    `  try { engine ??= await import(${JSON.stringify(engineUrl)}); }`,
    "  catch (err) { postMessage({ id, ok: false, stage: 'load', message: String(err?.message ?? err) }); return; }",
    '  try { postMessage({ id, ok: true, report: engine.analyzeInput(input) }); }',
    "  catch (err) { postMessage({ id, ok: false, stage: 'analyze', message: String(err?.message ?? err) }); }",
    '};',
    '',
  ].join('\n');
}

const abortError = () => {
  const e = new Error('análisis cancelado'); // i18n: ignore
  e.name = 'AbortError';
  return e;
};

/**
 * Analizador con un worker reutilizable y vuelta al hilo principal si el worker no está disponible.
 * `scope` existe para los tests: en la web es `globalThis` (Worker, Blob, URL, trustedTypes, location).
 *
 * run(input) → Promise<report>. Un run() nuevo cancela el anterior; cancel() termina el worker y rechaza la promesa
 * pendiente con un error de nombre AbortError. `mode` dice cómo se hizo el último análisis: 'worker' o 'main'.
 */
export function createAnalyzer({ analyze = analyzeInput, scope = globalThis, engineUrl = ENGINE_URL } = {}) {
  let worker = null;
  let blobUrl = null;
  let policy = null;
  let broken = !scope.Worker || !scope.Blob || !scope.URL?.createObjectURL;
  let seq = 0;
  let pending = null;
  const api = { mode: null, run, cancel, get available() { return !broken; } };

  function scriptUrl(url) {
    const tt = scope.trustedTypes;
    if (!tt?.createPolicy) return url;
    policy ??= tt.createPolicy(POLICY_NAME, {
      createScriptURL: (u) => {
        if (!isOwnBlobUrl(u, scope.location?.origin)) throw new TypeError('solo blob: del propio origen'); // i18n: ignore
        return u;
      },
    });
    return policy.createScriptURL(url);
  }

  function dispose() {
    worker?.terminate();
    worker = null;
    if (blobUrl) scope.URL.revokeObjectURL(blobUrl);
    blobUrl = null;
  }

  function spawn() {
    const blob = new scope.Blob([workerSource(engineUrl)], { type: 'text/javascript' });
    blobUrl = scope.URL.createObjectURL(blob);
    worker = new scope.Worker(scriptUrl(blobUrl), { type: 'module' });
    worker.onmessage = (e) => {
      const msg = e.data;
      if (!pending || msg?.id !== pending.id) return;
      const p = pending;
      pending = null;
      if (msg.ok) return p.resolve(msg.report);
      if (msg.stage === 'analyze') return p.reject(new Error(msg.message));
      // El worker no pudo cargar el motor: se da por roto y se termina en el hilo principal.
      giveUp(p);
    };
    worker.onerror = (e) => {
      e?.preventDefault?.();
      const p = pending;
      pending = null;
      // Con o sin análisis en curso, un worker que da error no se vuelve a usar.
      if (p) giveUp(p);
      else { broken = true; dispose(); }
    };
    worker.onmessageerror = worker.onerror;
    return worker;
  }

  /** El worker ha fallado: de aquí en adelante todo va por el hilo principal. */
  function giveUp(p) {
    broken = true;
    dispose();
    try {
      api.mode = 'main';
      p.resolve(analyze(p.input));
    } catch (err) {
      p.reject(err);
    }
  }

  function run(input) {
    cancel();
    if (broken) {
      api.mode = 'main';
      return Promise.resolve().then(() => analyze(input));
    }
    return new Promise((resolve, reject) => {
      const id = ++seq;
      pending = { id, input, resolve, reject };
      try {
        (worker ?? spawn()).postMessage({ id, input });
        api.mode = 'worker';
      } catch {
        // Sin política de Trusted Types posible, o postMessage no pudo clonar la entrada.
        pending = null;
        giveUp({ input, resolve, reject });
      }
    });
  }

  function cancel() {
    if (!pending) return false;
    const p = pending;
    pending = null;
    // Terminar es la única forma de parar un análisis a medias; el siguiente run() crea otro worker.
    dispose();
    p.reject(abortError());
    return true;
  }

  return api;
}
