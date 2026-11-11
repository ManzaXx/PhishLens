// Español e inglés (spec 3.1): idioma del navegador, botón ES / EN, recuerdo y localStorage bloqueado.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from './server.js';
import { openBrowser } from './browser.js';
import { SAMPLES } from '../../samples/index.js';
import { readFileSync } from 'node:fs';

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

const title03 = () => SAMPLES.find((s) => s.id === '03-phishing-banco').title;

test('en un análisis: pasa a inglés sin volver a analizar, la ruta sigue en #analista y avisa una vez', { skip }, async () => {
  const { context, page, errors } = await open({ locale: 'es-ES' });
  await page.locator('#history-toggle').check();
  await page.locator('#history-status', { hasText: 'Historial activado.' }).waitFor();
  await page.getByRole('button', { name: title03(), exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#history-open').textContent === 'Ver historial (1)');
  await page.locator('#report [data-action="mode-analyst"]').first().click();
  await page.locator('#report nav').waitFor();
  await page.locator('#lang-toggle').click();
  await page.locator('#report [aria-haspopup="menu"]', { hasText: 'Export' }).waitFor();
  assert.equal(new URL(page.url()).hash, '#analista');
  assert.equal(await page.locator('#report nav').getAttribute('aria-label'), 'Report sections');
  assert.match(await page.locator('#report nav').innerText(), /Signals[\s\S]*Dashboard/);
  assert.equal(await page.locator('#report .view__title').textContent(), 'Summary');
  // No hay un análisis nuevo en el historial, y los avisos de antes (regiones vivas) no se repiten:
  // el lector de pantalla solo oye el cambio de idioma (Review Focus 5).
  assert.equal(await page.locator('#history-status').textContent(), '');
  assert.equal(await page.locator('#history-open').textContent(), 'View history (1)');
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'lang-toggle');
  // Review Focus 5: el aviso dice exactamente el idioma nuevo.
  await page.waitForFunction(() => document.querySelector('#report-status').textContent === 'Language: English');
  await page.locator('#report nav a[href="#analista/senales"]').click();
  await page.locator('#report .view--senales').waitFor();
  assert.equal(new URL(page.url()).hash, '#analista/senales');
  assert.equal(await page.locator('#report .view__title').textContent(), 'Signals');
  assert.deepEqual(errors, []);
  await context.close();
});

test('Review Focus 4: las notas forenses sobreviven al cambio de idioma', { skip }, async () => {
  const { context, page, errors } = await open({ locale: 'es-ES' });
  await page.getByRole('button', { name: title03(), exact: true }).click();
  await page.locator('#report .verdict-card').waitFor();
  await page.locator('#report [aria-haspopup="menu"]').click();
  await page.getByRole('menuitem', { name: 'Informe forense' }).click();
  await page.locator('[data-role="forensic-notes"]').fill('Caso 2026-201');
  await page.getByRole('button', { name: 'Cerrar' }).click();
  await page.locator('#lang-toggle').click();
  await page.locator('#report [aria-haspopup="menu"]', { hasText: 'Export' }).click();
  await page.getByRole('menuitem', { name: 'Forensic report' }).click();
  assert.equal(await page.locator('[data-role="forensic-notes"]').inputValue(), 'Caso 2026-201');
  await page.getByRole('button', { name: 'Close' }).click();
  assert.deepEqual(errors, []);
  await context.close();
});

test('al cambiar de idioma, el fichero elegido sigue y el error de antes se quita', { skip }, async () => {
  const { context, page, errors } = await open({ locale: 'es-ES' });
  await page.locator('#tab-url').click();
  await page.locator('#analyze-btn').click();
  await page.locator('#input-error', { hasText: 'Escribe una URL.' }).waitFor();
  await page.locator('#lang-toggle').click();
  // El error era de la acción anterior y es role="alert": se quita en vez de volver a gritarlo.
  assert.equal(await page.locator('#input-error').isHidden(), true);
  assert.equal(await page.locator('#input-error').textContent(), '');
  await page.locator('#tab-eml').click();
  await page.locator('#file-input').setInputFiles({ name: 'prueba.eml', mimeType: 'message/rfc822', buffer: Buffer.from('From: a@b.c\nSubject: hola\n\nhola') });
  await page.locator('#report .verdict-card').waitFor();
  assert.equal(await page.locator('.dropzone__title').textContent(), 'prueba.eml');
  assert.match(await page.locator('.dropzone__hint').textContent(), /^0\.\d KB · ready to analyze$/);
  await page.locator('#lang-toggle').click();
  assert.equal(await page.locator('.dropzone__title').textContent(), 'prueba.eml');
  // El separador decimal sigue al idioma también en lo ya escrito.
  assert.match(await page.locator('.dropzone__hint').textContent(), /^0,\d KB · listo para analizar$/);
  assert.deepEqual(errors, []);
  await context.close();
});

test('cambiar de idioma no borra lo que el analista tenía a medias', { skip }, async () => {
  const { context, page, errors } = await open({ locale: 'es-ES' });
  // Vista previa de reglas sin activar.
  await page.locator('#rules > summary').click();
  await page.locator('#rules-file').setInputFiles({ name: 'reglas.json', mimeType: 'application/json', buffer: readFileSync(new URL('../../samples/rules/ejemplo.json', import.meta.url)) });
  await page.getByRole('button', { name: 'Activar reglas' }).waitFor();
  await page.locator('#lang-toggle').click();
  await page.locator('#rules-panel').getByRole('button', { name: 'Turn on rules' }).waitFor();
  // Registros DNS pegados en «Check locally» y una búsqueda sin enviar.
  await page.getByRole('button', { name: title03(), exact: true }).click();
  await page.locator('#report .verdict-card').waitFor();
  await page.goto(`${server.url}/index.html#analista/autenticacion`);
  await page.locator('#report .view--autenticacion').waitFor();
  await page.locator('#report details.auth-local summary').click();
  await page.locator('#dkim-key').fill('v=DKIM1; k=rsa; p=ABC');
  await page.locator('#spf-record').fill('v=spf1 -all');
  await page.locator('#lang-toggle').click();
  await page.locator('#report .view__title', { hasText: 'Autenticación' }).waitFor();
  assert.equal(await page.locator('#dkim-key').inputValue(), 'v=DKIM1; k=rsa; p=ABC');
  assert.equal(await page.locator('#spf-record').inputValue(), 'v=spf1 -all');
  assert.equal(await page.locator('#report details.auth-local').getAttribute('open'), '');
  assert.deepEqual(errors, []);
  await context.close();
});
