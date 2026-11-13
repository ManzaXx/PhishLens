// El worker de análisis (ADR 0007) en un navegador real: hereda la CSP del documento (nada sale del origen, ni
// siquiera desde dentro del worker), Trusted Types solo deja crear la política de la app, el informe del worker
// es el mismo que el del hilo principal, y en la app «Analizar» muestra «Analizando…» y se puede cancelar.
//
// Motores: E2E_BROWSERS=chromium,firefox,webkit (por defecto, chromium). En CI un motor que no arranque es un fallo.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { serve } from './server.js';
import { selfSignedCert } from './tls.js';
import { loadPlaywright, warnSkipped, withSpanishLocale } from './browser.js';

const ENGINES = (process.env.E2E_BROWSERS ?? 'chromium').split(',').map((s) => s.trim()).filter(Boolean);
const loaded = loadPlaywright();
if (loaded.skip) warnSkipped(loaded.skip);
const INDEX_CSP = readFileSync(new URL('../../index.html', import.meta.url), 'utf8').match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];

async function launch(name) {
  if (loaded.skip) return { skip: loaded.skip };
  try {
    return { browser: withSpanishLocale(await loaded.playwright[name].launch()) };
  } catch (e) {
    if (process.env.CI) throw e;
    const skip = `${name} no arranca (${String(e.message).split('\n')[0]}); instala con npx playwright install ${name}`;
    warnSkipped(skip);
    return { skip };
  }
}

// Los navegadores se abren antes de registrar ningún test: si un test termina mientras aún se está lanzando un
// motor, node:test da la suite por acabada y cierra el servidor antes de tiempo.
const LAUNCHED = new Map();
for (const engine of ENGINES) LAUNCHED.set(engine, await launch(engine));
let server;

// Por HTTPS, como en producción (GitHub Pages): WebKit aplica `upgrade-insecure-requests` también a 127.0.0.1 y por
// HTTP no cargaría ni un script. El certificado es autofirmado y efímero; los contextos lo aceptan (ignoreHTTPSErrors).
const TLS = selfSignedCert();
if (!TLS) process.stderr.write('\n(ℹ︎ sin openssl: los tests del worker se sirven por HTTP; en WebKit fallarían)\n');

before(async () => { server = await serve(undefined, { tls: TLS }); });
after(async () => { await server?.close(); });

/** Las páginas de prueba deben llevar exactamente la CSP de index.html: si no, no prueban nada. */
for (const fixture of ['csp-probe.html', 'app-worker.html']) {
  test(`tests/fixtures/worker/${fixture} lleva la misma CSP que index.html`, () => {
    const html = readFileSync(new URL(`../fixtures/worker/${fixture}`, import.meta.url), 'utf8');
    assert.equal(html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1], INDEX_CSP);
  });
}

/**
 * Contexto que distingue lo que SALIÓ del navegador (llegó al route handler) de lo que el navegador creó y cortó por
 * CSP antes de salir (evento request + requestfailed). Un import remoto bloqueado aparece como lo segundo tanto
 * desde el documento como desde el worker: es cómo Playwright enseña una petición cortada, no una fuga.
 */
async function probeContext(browser, origin) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const routed = [];
  const requested = [];
  const finished = [];
  const all = [];
  const own = (url) => url.startsWith(`${origin}/`) || url.startsWith('blob:') || url.startsWith('data:');
  await context.route('**/*', (route) => {
    const url = route.request().url();
    if (own(url)) return route.continue();
    routed.push(url);
    return route.abort('blockedbyclient');
  });
  context.on('request', (r) => { all.push(r.url()); if (!own(r.url())) requested.push(r.url()); });
  context.on('requestfailed', (r) => { all.push(`FALLÓ ${r.url()} (${r.failure()?.errorText})`); });
  context.on('requestfinished', (r) => { if (!own(r.url())) finished.push(r.url()); });
  const page = await context.newPage();
  page.setDefaultTimeout(20000);
  const errors = [];
  const consoleLog = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') consoleLog.push(`${m.type()}: ${m.text()}`); });
  return { context, page, routed, requested, finished, errors, consoleLog, all };
}

/**
 * Espera a que la página deje `window[key]`. Si no llega, el fallo cuenta lo que sí había (`window[partialKey]`),
 * los errores y la consola: en un motor que no se puede abrir en local es la única pista.
 */
async function awaitResult(c, key, partialKey) {
  try {
    await c.page.waitForFunction((k) => window[k], key, { timeout: 30000 });
  } catch (e) {
    const partial = await c.page.evaluate((k) => window[k] ?? null, partialKey).catch(() => 'sin acceso');
    const dom = await c.page.evaluate(() => ({ ready: document.readyState, scripts: [...document.scripts].map((s) => s.src), trustedTypes: typeof trustedTypes, worker: typeof Worker })).catch((err) => String(err));
    assert.fail(`${e.message.split('\n')[0]}\n  parcial: ${JSON.stringify(partial)}\n  dom: ${JSON.stringify(dom)}\n  peticiones: ${JSON.stringify(c.all)}\n  errores: ${JSON.stringify(c.errors)}\n  consola: ${JSON.stringify(c.consoleLog)}`);
  }
  return c.page.evaluate((k) => window[k], key);
}

for (const [engine, { browser, skip }] of LAUNCHED) {
  after(async () => { await browser?.close(); });

  test(`[${engine}] el worker hereda la CSP: nada sale del origen desde dentro del worker`, { skip }, async () => {
    const c = await probeContext(browser, server.url);
    await c.page.goto(`${server.url}/tests/fixtures/worker/csp-probe.html`);
    const probe = await awaitResult(c, '__probe', '__probePartial');
    const w = probe.worker;
    assert.equal(typeof w, 'object', `el worker no contestó: ${JSON.stringify(probe)}`);
    assert.equal(w.engineLoaded, true, 'el motor (mismo origen) sí se importa dentro del worker');
    for (const k of ['fetchSameOrigin', 'fetchRemote', 'importRemote', 'xhr', 'websocket', 'evalInWorker', 'importScripts']) {
      assert.match(String(w[k]), /^bloqueado/, `${k}: ${w[k]}`);
    }
    assert.ok(w.violations.some((v) => v.startsWith('connect-src')), `sin violación connect-src dentro del worker: ${w.violations}`);
    // El import remoto lo corta script-src (Chromium, WebKit) o worker-src (Firefox); el eval, script-src.
    assert.ok(w.violations.some((v) => /^(script-src|worker-src)/.test(v)), `sin violación script-src/worker-src dentro del worker: ${w.violations}`);
    assert.equal(typeof w.engineScore, 'number');
    assert.match(String(probe.documentImportRemote), /^bloqueado/);
    // Nada llegó a salir: el route handler no vio ninguna petición ajena y ninguna terminó.
    assert.deepEqual(c.routed, [], 'peticiones que salieron del navegador');
    assert.deepEqual(c.finished, [], 'peticiones ajenas que terminaron');
    // Las que el navegador creó y cortó solo pueden ser los dos imports remotos de la sonda.
    for (const u of c.requested) assert.match(u, /^https:\/\/leak\.example\//, `petición inesperada ${u}`);
    assert.equal(probe.appWorkerSourceHasNoEval, true);
    await c.context.close();
  });

  test(`[${engine}] Trusted Types: solo la política de la app, y solo blob: propio`, { skip }, async () => {
    const c = await probeContext(browser, server.url);
    await c.page.goto(`${server.url}/tests/fixtures/worker/csp-probe.html`);
    const probe = await awaitResult(c, '__probe', '__probePartial');
    if (probe.trustedTypes) {
      assert.match(String(probe.workerWithoutPolicy), /^rechazado: TypeError/, 'new Worker con una cadena debe fallar');
      assert.equal(probe.policyCreated, true);
      assert.match(String(probe.otherPolicy), /^rechazada: TypeError/);
      assert.match(String(probe.duplicatePolicy), /^rechazada: TypeError/);
      assert.match(String(probe.policyRemote), /^rechazado: TypeError/);
    } else {
      // Sin Trusted Types el navegador no aplica nada aquí: la CSP heredada sigue siendo la barrera real.
      // Se deja constancia en el resumen para saber en qué motores se probó.
      process.stderr.write(`\n(ℹ︎ ${engine} no implementa Trusted Types: solo se comprueba la CSP heredada)\n`);
      assert.equal(probe.workerWithoutPolicy, 'CREADO');
    }
    await c.context.close();
  });

  test(`[${engine}] el analizador real: mismo informe en el worker que en el hilo principal, y cancelar funciona`, { skip }, async () => {
    const c = await probeContext(browser, server.url);
    await c.page.goto(`${server.url}/tests/fixtures/worker/app-worker.html`);
    const app = await awaitResult(c, '__app', '__appPartial');
    assert.equal(app.error, undefined, app.error);
    assert.equal(app.available, true);
    assert.equal(app.mode, 'worker', `el análisis debe hacerse en el worker, no caer al hilo principal (motivo: ${app.lastError}; errores: ${JSON.stringify(c.errors)}; consola: ${JSON.stringify(c.consoleLog)})`);
    assert.equal(app.sameAsMain, true);
    assert.equal(app.cancelled, true);
    assert.equal(app.cancelError, 'AbortError');
    assert.equal(app.afterCancel, app.score);
    assert.equal(app.modeAfterCancel, 'worker');
    assert.deepEqual(c.routed, []);
    assert.deepEqual(c.requested, []);
    assert.deepEqual(c.errors, []);
    await c.context.close();
  });

  test(`[${engine}] en la app, «Analizar» usa el worker y «Cancelar» corta un análisis largo`, { skip }, async () => {
    const c = await probeContext(browser, server.url);
    await c.page.goto(`${server.url}/index.html`);
    // Un análisis normal: termina, y el informe dice que lo hizo el worker.
    await c.page.locator('#tab-text').click();
    try {
      await c.page.locator('#raw-input').waitFor({ state: 'visible', timeout: 5000 });
    } catch {
      assert.fail(`la pestaña Texto no se abre; peticiones: ${JSON.stringify(c.all)}; errores: ${JSON.stringify(c.errors)}; consola: ${JSON.stringify(c.consoleLog)}`);
    }
    await c.page.locator('#raw-input').fill('Verifica tu cuenta urgentemente: http://203.0.113.9/login');
    await c.page.locator('#analyze-btn').click();
    await c.page.locator('#report .verdict-card').waitFor();
    assert.equal(await c.page.getAttribute('#report', 'data-analyzed-by'), 'worker', `errores: ${JSON.stringify(c.errors)}; consola: ${JSON.stringify(c.consoleLog)}`);
    assert.equal(await c.page.locator('#analyze-status').isHidden(), true);
    assert.equal(await c.page.locator('#analyze-btn').isDisabled(), false);
    const first = await c.page.locator('#report .verdict-card').textContent();
    // Un correo de 8 MB con muchas URL, cargado como fichero (un textarea con 8 MB haría lenta a la propia página,
    // y eso no es lo que se mide): tarda lo bastante para que se vea «Analizando…» y se pueda cancelar.
    const big = Buffer.from(`From: a@b.example\nSubject: hola\n\n${'Mira http://203.0.113.9/login y http://ejemplo-largo.example/ruta\n'.repeat(130000)}`);
    await c.page.locator('#tab-eml').click();
    await c.page.locator('#file-input').setInputFiles({ name: 'grande.eml', mimeType: 'message/rfc822', buffer: big });
    await c.page.locator('#analyze-status').waitFor({ state: 'visible' });
    assert.equal(await c.page.locator('#analyze-status').textContent(), 'Analizando…Cancelar');
    assert.equal(await c.page.locator('#analyze-btn').isDisabled(), true);
    // La página responde mientras el worker trabaja: el clic en Cancelar se atiende enseguida.
    const t0 = Date.now();
    await c.page.locator('#analyze-cancel').click();
    await c.page.locator('#analyze-status').waitFor({ state: 'hidden' });
    const elapsed = Date.now() - t0;
    assert.equal(await c.page.locator('#analyze-btn').isDisabled(), false);
    assert.equal(await c.page.locator('#report .verdict-card').textContent(), first, 'cancelar no cambia el informe que había');
    assert.equal(await c.page.locator('#input-error').isHidden(), true, 'cancelar no es un error');
    await c.page.waitForFunction(() => document.querySelector('#report-status').textContent.includes('cancelado'), null, { timeout: 3000 });
    assert.ok(elapsed < 2000, `cancelar tardó ${elapsed} ms en atenderse: la página no respondía`);
    // Y después se puede seguir analizando con normalidad.
    await c.page.locator('#tab-text').click();
    await c.page.locator('#raw-input').fill('https://ejemplo.example/');
    await c.page.locator('#analyze-btn').click();
    await c.page.waitForFunction((prev) => document.querySelector('#report .verdict-card')?.textContent !== prev, first);
    assert.deepEqual(c.routed, []);
    assert.deepEqual(c.requested, []);
    assert.deepEqual(c.errors, []);
    process.stderr.write(`\n(ℹ︎ ${engine}: cancelar un análisis de 8 MB tardó ${elapsed} ms en atenderse)\n`);
    await c.context.close();
  });
}
