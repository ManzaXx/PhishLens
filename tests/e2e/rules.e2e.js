// Reglas propias en un Chromium real (spec 3.0, §5.2 y §7): cargar, probar y activar; errores; guardado con
// el historial y borrado con «Borrar todo»; migración de la base v1; privacidad, axe y teclado.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { serve } from './server.js';
import { openBrowser, watchedPage } from './browser.js';
import { SAMPLES } from '../../samples/index.js';

const AXE = process.env.AXE_PATH ?? fileURLToPath(new URL('../../node_modules/axe-core/axe.min.js', import.meta.url));
const noAxe = existsSync(AXE) ? false : `axe-core no está en ${AXE} (npm ci o AXE_PATH)`;
if (noAxe && process.env.CI) throw new Error(noAxe);
const { browser, skip: noBrowser } = noAxe ? {} : await openBrowser();
const skip = noAxe || noBrowser || false;
const EXAMPLE = readFileSync(new URL('../../samples/rules/ejemplo.json', import.meta.url));
const BAD = Buffer.from(EXAMPLE.toString('utf8').replace('"op": "contains"', '"op": "matches"'));
const title = (id) => SAMPLES.find((s) => s.id === id).title;
const file = (buffer, name = 'reglas.json') => ({ name, mimeType: 'application/json', buffer });
let server;

before(async () => {
  if (skip) return;
  server = await serve();
});
after(async () => {
  await browser?.close();
  await server?.close();
});

async function axe(page) {
  await page.evaluate(readFileSync(AXE, 'utf8'));
  const { violations } = await page.evaluate(() => window.axe.run(document, { resultTypes: ['violations'] }));
  return violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
}
const databases = (page) => page.evaluate(async () => (await indexedDB.databases()).map((d) => d.name));

async function home(page, hash = '') {
  page.setDefaultTimeout(8000);
  await page.goto(`${server.url}/index.html${hash}`);
}
async function load(page, buffer) {
  if (!(await page.locator('#rules').evaluate((d) => d.open))) await page.locator('#rules > summary').click();
  await page.locator('#rules-file').setInputFiles(file(buffer));
}
async function activate(page) {
  await load(page, EXAMPLE);
  await page.getByRole('button', { name: 'Activar reglas' }).click();
  await page.locator('#rules-panel', { hasText: '3 reglas activas' }).waitFor();
}

test('cargar, ver la vista previa y activar: la muestra 03 gana «Regla propia»; privacidad y axe', { skip }, async () => {
  for (const colorScheme of ['light', 'dark']) {
    const w = await watchedPage(browser, server.url, { colorScheme });
    await home(w.page, '#analista');
    await load(w.page, EXAMPLE);
    await w.page.locator('#rules-panel', { hasText: '3 reglas válidas' }).waitFor();
    assert.match(await w.page.locator('#rules-panel').innerText(), /No se puede probar: el historial no guarda el correo/);
    assert.match(await w.page.locator('#rules-panel').innerText(), /Sin análisis guardados para probarla/);
    assert.equal(await w.page.evaluate(() => document.activeElement?.classList.contains('rules__summary')), true, 'el foco va al resumen');
    assert.deepEqual(await axe(w.page), [], `axe en la vista previa (${colorScheme})`);
    await w.page.getByRole('button', { name: 'Activar reglas' }).click();
    await w.page.locator('#rules-panel', { hasText: '3 reglas activas' }).waitFor();
    await w.page.getByRole('button', { name: title('03-phishing-banco'), exact: true }).click();
    await w.page.locator('#report .report__toolbar').waitFor();
    await w.page.evaluate(() => { location.hash = '#analista/senales'; });
    await w.page.locator('#report .finding__custom').first().waitFor();
    assert.match(await w.page.locator('#report').innerText(), /Dominio parecido a una marca y un enlace sospechoso/);
    assert.deepEqual(await axe(w.page), [], `axe en las señales con una regla propia (${colorScheme})`);
    assert.ok(!(await databases(w.page)).includes('phishlens'), 'sin historial no se crea la base');
    assert.deepEqual(w.external, [], 'peticiones fuera del origen');
    assert.deepEqual(await w.violations(), [], 'violaciones de CSP');
    assert.deepEqual(w.errors, [], 'errores de JavaScript');
    await w.context.close();
  }
});

test('un fichero inválido enseña sus errores y no activa nada', { skip }, async () => {
  const w = await watchedPage(browser, server.url);
  await home(w.page);
  await load(w.page, BAD);
  const alert = w.page.locator('#rules-panel [role="alert"]');
  await alert.waitFor();
  assert.match(await alert.innerText(), /Regla 1, `when\.all\[0\]\.op`: «matches» no es un operador admitido/);
  assert.equal(await w.page.getByRole('button', { name: 'Activar reglas' }).count(), 0);
  assert.equal(await w.page.evaluate(() => document.activeElement?.getAttribute('role')), 'alert');
  assert.deepEqual(await axe(w.page), []);
  await w.context.close();
});

test('Review Focus 5: con historial, las reglas siguen tras recargar y se van con «Borrar todo»', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await home(page);
  await page.locator('#history-toggle').check();
  await page.locator('#history-status', { hasText: 'Historial activado.' }).waitFor();
  await activate(page);
  assert.match(await page.locator('#rules-status').innerText(), /Se guardan con el historial/);
  await page.getByRole('button', { name: title('03-phishing-banco'), exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#history-open').textContent === 'Ver historial (1)');
  await page.reload();
  await page.locator('#rules-panel', { hasText: '3 reglas activas' }).waitFor({ state: 'attached' });
  await page.getByRole('button', { name: 'Ver historial (1)' }).click();
  await page.locator('#report .history__table').waitFor();
  await page.getByRole('button', { name: 'Borrar todo' }).click();
  await page.getByRole('button', { name: 'Borrar 1 análisis' }).click();
  await page.locator('#rules-panel', { hasText: 'No hay reglas propias cargadas.' }).waitFor({ state: 'attached' });
  await page.waitForFunction(async () => !(await indexedDB.databases()).some((d) => d.name === 'phishlens'));
  await page.reload();
  await page.locator('#rules-panel', { hasText: 'No hay reglas propias cargadas.' }).waitFor({ state: 'attached' });
  await context.close();
});

test('«Quitar reglas» las quita de la pestaña y de la base', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await home(page);
  await page.locator('#history-toggle').check();
  await page.locator('#history-status', { hasText: 'Historial activado.' }).waitFor();
  await activate(page);
  await page.getByRole('button', { name: 'Quitar reglas' }).click();
  await page.locator('#rules-status', { hasText: 'Reglas propias quitadas.' }).waitFor();
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'rules-load');
  await page.reload();
  await page.locator('#rules-panel', { hasText: 'No hay reglas propias cargadas.' }).waitFor({ state: 'attached' });
  await context.close();
});

test('una base de la versión 1 se migra a la 2 sin perder lo guardado', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await home(page);
  await page.locator('#history-toggle').check();
  await page.locator('#history-status', { hasText: 'Historial activado.' }).waitFor();
  await page.getByRole('button', { name: title('03-phishing-banco'), exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#history-open').textContent === 'Ver historial (1)');
  // Se rehace la base como era en la v1 (sin «rules»), con la misma entrada dentro.
  await page.evaluate(async () => {
    const req = (r) => new Promise((ok, ko) => { r.onsuccess = () => ok(r.result); r.onerror = () => ko(r.error); });
    const db2 = await req(indexedDB.open('phishlens'));
    const rows = await req(db2.transaction('analyses').objectStore('analyses').getAll());
    db2.close();
    await req(indexedDB.deleteDatabase('phishlens'));
    const open = indexedDB.open('phishlens', 1);
    open.onupgradeneeded = () => {
      const s = open.result.createObjectStore('analyses', { keyPath: 'id' });
      s.createIndex('savedAt', 'savedAt');
      s.createIndex('sha256', 'sha256', { unique: true });
      s.createIndex('level', 'report.level');
      open.result.createObjectStore('batches', { keyPath: 'id' });
    };
    const db1 = await req(open);
    const tx = db1.transaction('analyses', 'readwrite');
    for (const r of rows) tx.objectStore('analyses').put(r);
    await new Promise((ok) => { tx.oncomplete = ok; });
    db1.close();
  });
  await page.reload();
  await page.getByRole('button', { name: 'Ver historial (1)' }).waitFor();
  const info = await page.evaluate(async () => {
    const db = await new Promise((ok) => { const r = indexedDB.open('phishlens'); r.onsuccess = () => ok(r.result); });
    const out = { version: db.version, stores: [...db.objectStoreNames] };
    db.close();
    return out;
  });
  assert.equal(info.version, 2);
  assert.deepEqual(info.stores.sort(), ['analyses', 'batches', 'rules']);
  await activate(page);
  await context.close();
});

test('teclado: Tab llega a «Reglas propias» y a «Cargar reglas»; Enter abre el selector', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await home(page);
  await page.locator('#history-toggle').focus();
  let guard = 0;
  while (!(await page.evaluate(() => document.activeElement?.matches('#rules > summary'))) && guard++ < 10) await page.keyboard.press('Tab');
  assert.ok(guard < 10, 'Tab no llega al resumen de «Reglas propias»');
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#rules').evaluate((d) => d.open), true);
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'rules-load');
  // Enter en «Cargar reglas» abre el selector de ficheros (el clic llega al input); el fichero se pone a mano
  // porque el evento filechooser de Playwright no es fiable con varios navegadores a la vez.
  await page.evaluate(() => {
    window.__rulesPicker = 0;
    document.querySelector('#rules-file').addEventListener('click', (e) => { window.__rulesPicker++; e.preventDefault(); });
  });
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => window.__rulesPicker === 1);
  await page.locator('#rules-file').setInputFiles(file(EXAMPLE));
  await page.locator('#rules-panel', { hasText: '3 reglas válidas' }).waitFor();
  assert.equal(await page.evaluate(() => document.activeElement?.classList.contains('rules__summary')), true);
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement?.textContent), 'Activar reglas');
  await context.close();
});
