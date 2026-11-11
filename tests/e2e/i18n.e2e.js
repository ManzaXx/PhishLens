// Español e inglés (spec 3.1): idioma del navegador, botón ES / EN, recuerdo y localStorage bloqueado.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from './server.js';
import { openBrowser } from './browser.js';

const { browser, skip } = await openBrowser();
let server;
before(async () => { if (!skip) server = await serve(); });
after(async () => { await browser?.close(); await server?.close(); });

async function open(options) {
  const context = await browser.newContext(options);
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  await page.goto(`${server.url}/index.html`);
  return { context, page, errors };
}

const h1 = (page) => page.locator('h1').textContent();

test('la portada sale en el idioma del navegador', { skip }, async () => {
  const en = await open({ locale: 'en-US' });
  assert.equal(await en.page.getAttribute('html', 'lang'), 'en');
  assert.match(await h1(en.page), /Is it phishing\?/);
  assert.doesNotMatch(await h1(en.page), /Compruébalo/);
  assert.equal(await en.page.title(), 'PhishLens · Phishing analyzer');
  await en.context.close();
  const es = await open({ locale: 'es-ES' });
  assert.equal(await es.page.getAttribute('html', 'lang'), 'es');
  assert.match(await h1(es.page), /Compruébalo/);
  await es.context.close();
});

test('el botón cambia de idioma, mide 44 px y se recuerda al recargar', { skip }, async () => {
  const { context, page, errors } = await open({ locale: 'es-ES' });
  const btn = page.locator('#lang-toggle');
  assert.equal(await btn.textContent(), 'EN · Switch to English');
  assert.equal(await btn.evaluate((b) => b.firstChild.textContent), 'EN');
  assert.equal(await btn.getAttribute('lang'), 'en');
  const box = await btn.boundingBox();
  assert.ok(box.width >= 44 && box.height >= 44, `${box.width}×${box.height}`);
  await btn.click();
  assert.equal(await page.getAttribute('html', 'lang'), 'en');
  assert.match(await h1(page), /Is it phishing\?/);
  assert.equal(await page.locator('#analyze-btn').textContent(), 'Analyze');
  assert.equal(await btn.evaluate((b) => b.firstChild.textContent), 'ES');
  assert.equal(await btn.textContent(), 'ES · Cambiar a español');
  assert.equal(await btn.getAttribute('lang'), 'es');
  await page.reload();
  assert.equal(await page.getAttribute('html', 'lang'), 'en');
  assert.deepEqual(errors, []);
  await context.close();
});

test('Review Focus 2: con localStorage bloqueado arranca en el idioma del navegador y el botón funciona', { skip }, async () => {
  const context = await browser.newContext({ locale: 'en-GB' });
  await context.addInitScript(() => {
    Object.defineProperty(window, 'localStorage', { get() { throw new DOMException('bloqueado', 'SecurityError'); } });
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(`${server.url}/index.html`);
  assert.equal(await page.getAttribute('html', 'lang'), 'en');
  await page.locator('#lang-toggle').click();
  assert.equal(await page.getAttribute('html', 'lang'), 'es');
  assert.deepEqual(errors, []);
  await context.close();
});
