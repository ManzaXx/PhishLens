// Privacidad en un Chromium real (spec 2.2, §8.6): analizar un correo no hace ni una petición fuera del origen.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { serve } from './server.js';
import { openBrowser, watchedPage } from './browser.js';
import { SAMPLES } from '../../samples/index.js';

const { browser, skip } = await openBrowser();
const REMOTE = readFileSync(new URL('../fixtures/privacy/remote-content.eml', import.meta.url), 'utf8');
let server;

before(async () => {
  if (skip) return;
  server = await serve();
});
after(async () => {
  await browser?.close();
  await server?.close();
});

/** Recorre el modo sencillo y cada vista del modo analista, incluida la vista segura, y deja que pinte. */
async function visitAllReportTabs(page) {
  await page.locator('#report .verdict-card').waitFor();
  await page.locator('#report [data-action="mode-analyst"]').first().click();
  const links = page.locator('#report nav a');
  await links.first().waitFor();
  const count = await links.count();
  assert.ok(count >= 5, `solo ${count} vistas`);
  for (let i = 0; i < count; i++) {
    await links.nth(i).click();
    await page.waitForTimeout(30);
  }
  // El menú Exportar se abre y se cierra sin hacer nada fuera.
  await page.locator('#report [aria-haspopup="menu"]').click();
  await page.locator('#report [role="menu"]').waitFor();
  await page.keyboard.press('Escape');
  await page.locator('#report [data-action="mode-simple"]').click();
  await page.locator('#report .verdict-card').waitFor();
}

async function assertClean(w, what) {
  await w.page.waitForTimeout(200);
  assert.deepEqual(w.external, [], `${what}: peticiones fuera del origen`);
  assert.deepEqual(await w.violations(), [], `${what}: violaciones de CSP`);
  assert.deepEqual(w.errors, [], `${what}: errores de JavaScript`);
}

test('control negativo: una página que filtra datos es detectada', { skip }, async () => {
  const w = await watchedPage(browser, server.url);
  await w.page.goto(`${server.url}/tests/fixtures/privacy/leaky.html`);
  await w.page.waitForTimeout(300);
  assert.ok(w.external.some((u) => u.startsWith('https://leak.example/')), `no se vio la fuga: ${w.external}`);
  await w.context.close();
});

for (const colorScheme of ['light', 'dark']) {
  test(`las ${SAMPLES.length} muestras no hacen peticiones externas (${colorScheme})`, { skip }, async () => {
    const w = await watchedPage(browser, server.url, { colorScheme });
    await w.page.goto(`${server.url}/index.html`);
    for (const sample of SAMPLES) {
      await w.page.getByRole('button', { name: sample.title, exact: true }).click();
      await visitAllReportTabs(w.page);
    }
    await assertClean(w, `muestras en ${colorScheme}`);
    await w.context.close();
  });

  test(`un correo lleno de contenido remoto pegado a mano no carga nada (${colorScheme})`, { skip }, async () => {
    const w = await watchedPage(browser, server.url, { colorScheme });
    await w.page.goto(`${server.url}/index.html`);
    await w.page.locator('#tab-text').click();
    await w.page.locator('#raw-input').fill(REMOTE);
    await w.page.locator('#analyze-btn').click();
    await visitAllReportTabs(w.page);
    await w.page.locator('#theme-toggle').click();
    await visitAllReportTabs(w.page);
    await assertClean(w, `contenido remoto en ${colorScheme}`);
    await w.context.close();
  });
}

test('en inglés, las muestras tampoco hacen peticiones externas', { skip }, async () => {
  const w = await watchedPage(browser, server.url, { locale: 'en-GB' });
  await w.page.goto(`${server.url}/index.html`);
  assert.equal(await w.page.getAttribute('html', 'lang'), 'en');
  for (const sample of SAMPLES) {
    await w.page.getByRole('button', { name: sample.titleEn, exact: true }).click();
    await visitAllReportTabs(w.page);
  }
  // Y el cambio de idioma en sí tampoco pide nada: los dos diccionarios ya van en la página.
  await w.page.locator('#lang-toggle').click();
  await w.page.locator('#lang-toggle').click();
  await assertClean(w, 'muestras en inglés');
  await w.context.close();
});

test('la página no puede abrir conexiones, ni siquiera con su propio origen', { skip }, async () => {
  const w = await watchedPage(browser, server.url);
  await w.page.goto(`${server.url}/index.html`);
  const outcome = await w.page.evaluate(() => fetch('/index.html').then(() => 'conectó', () => 'bloqueado'));
  assert.equal(outcome, 'bloqueado');
  assert.ok((await w.violations()).some((v) => v.startsWith('connect-src')));
  await w.context.close();
});
