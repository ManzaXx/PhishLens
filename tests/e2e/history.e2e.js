// Historial en un Chromium real (spec 3.0, §2 y §7): apagado no crea la base, encendido sobrevive a la
// recarga, «Borrar todo» borra la base entera, exportar e importar, privacidad, axe, teclado y diseño.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { serve } from './server.js';
import { openBrowser, watchedPage } from './browser.js';
import { SAMPLES } from '../../samples/index.js';

const AXE = process.env.AXE_PATH ?? fileURLToPath(new URL('../../node_modules/axe-core/axe.min.js', import.meta.url));
const noAxe = existsSync(AXE) ? false : `axe-core no está en ${AXE} (npm ci o AXE_PATH)`;
if (noAxe && process.env.CI) throw new Error(noAxe);
const { browser, skip: noBrowser } = noAxe ? {} : await openBrowser();
const skip = noAxe || noBrowser || false;
const LOT = 'Lote de campaña (4 correos)';
const title = (id) => SAMPLES.find((s) => s.id === id).title;
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
const overflow = (page) => page.evaluate(() => document.documentElement.scrollWidth - innerWidth);

async function analyze(page, id) {
  await page.getByRole('button', { name: title(id), exact: true }).click();
  await page.locator('#report .verdict-card, #report .view').first().waitFor();
}

/** Espera a que el guardado termine (el contador de la portada cambia aunque esté oculto). */
const saved = (page, n) => page.waitForFunction((t) => document.querySelector('#history-open').textContent === t, `Ver historial (${n})`);

async function home(page) {
  await page.goto(`${page.__origin}/index.html`);
}

/** Abre una pestaña con el historial encendido y dos análisis guardados. */
async function withTwo(context, origin) {
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  page.__origin = origin;
  await home(page);
  await page.locator('#history-toggle').check();
  await page.locator('#history-status', { hasText: 'Historial activado.' }).waitFor();
  await analyze(page, '03-phishing-banco');
  await saved(page, 1);
  await home(page);
  await analyze(page, '04-phishing-correos');
  await saved(page, 2);
  await home(page);
  await page.getByRole('button', { name: 'Ver historial (2)' }).waitFor();
  return page;
}

async function openView(page) {
  await page.getByRole('button', { name: 'Ver historial (2)' }).click();
  await page.locator('#report .history__table').waitFor();
}

test('privacidad: con el historial apagado no se crea la base phishlens', { skip }, async () => {
  const w = await watchedPage(browser, server.url);
  w.page.setDefaultTimeout(8000);
  w.page.__origin = server.url;
  for (const id of ['01-legitimo-newsletter', '03-phishing-banco', '04-phishing-correos']) {
    await home(w.page);
    await analyze(w.page, id);
  }
  await home(w.page);
  await w.page.getByRole('button', { name: LOT, exact: true }).click();
  await w.page.locator('#report .batch-bar').waitFor();
  await w.page.waitForTimeout(200);
  assert.ok(!(await databases(w.page)).includes('phishlens'), 'la base existe con el historial apagado');
  assert.equal(await w.page.locator('#history-open').isHidden(), true);
  assert.deepEqual(w.external, [], 'peticiones fuera del origen');
  assert.deepEqual(await w.violations(), [], 'violaciones de CSP');
  assert.deepEqual(w.errors, [], 'errores de JavaScript');
  await w.context.close();
});

test('encendido: sobrevive a la recarga, se abre, se busca y se comparan dos', { skip }, async () => {
  const w = await watchedPage(browser, server.url);
  const page = await withTwo(w.context, server.url);
  await page.reload();
  await expectChecked(page);
  await openView(page);
  assert.equal(await page.locator('#report .history__table tbody tr').count(), 2);
  assert.match(await page.locator('#report .history__pager').innerText(), /Se muestran 1–2 de 2/);

  await page.locator('[data-role="history-query"]').fill('santander');
  await page.locator('[data-role="history-query"]').press('Enter');
  const hits = page.locator('#report .history__hits li');
  await hits.first().waitFor();
  assert.match(await hits.allInnerTexts().then((t) => t.join('\n')), /santander-seguridad\[\.\]test/);

  const boxes = page.locator('#report [data-action="history-select"]');
  await boxes.nth(0).check();
  await boxes.nth(1).check();
  await page.getByRole('button', { name: 'Comparar los dos marcados' }).click();
  await page.locator('#report .history__compare').waitFor();
  assert.match(await page.locator('#report .history__compare').innerText(), /Diferencia de puntuación/);

  await page.locator('#report [data-action="history-open"]').first().click();
  await page.locator('#report .saved-note').waitFor();
  assert.match(await page.locator('#report .saved-note').innerText(), /el correo original no está guardado/);
  assert.deepEqual(w.external, [], 'peticiones fuera del origen');
  assert.deepEqual(w.errors, [], 'errores de JavaScript');
  await w.context.close();
});

async function expectChecked(page) {
  await page.waitForFunction(() => document.querySelector('#history-toggle').checked);
  await page.getByRole('button', { name: 'Ver historial (2)' }).waitFor();
}

test('«Borrar todo» pide confirmación y borra la base entera', { skip }, async () => {
  const context = await browser.newContext();
  const page = await withTwo(context, server.url);
  await openView(page);
  assert.ok((await databases(page)).includes('phishlens'));
  await page.getByRole('button', { name: 'Borrar todo' }).click();
  const dialog = page.locator('#report .history__dialog');
  await dialog.waitFor();
  assert.match(await dialog.innerText(), /¿Borrar los 2 análisis guardados\? No se puede deshacer\./);
  await page.keyboard.press('Escape');
  await dialog.waitFor({ state: 'hidden' });
  assert.equal(await page.locator('#report .history__table tbody tr').count(), 2, 'Escape no borra');
  await page.getByRole('button', { name: 'Borrar todo' }).click();
  await page.getByRole('button', { name: 'Borrar 2 análisis' }).click();
  await page.locator('#report .empty-state').waitFor();
  await page.waitForFunction(async () => !(await indexedDB.databases()).some((d) => d.name === 'phishlens'));
  // El interruptor sigue encendido: el siguiente análisis vuelve a crear la base.
  await home(page);
  await analyze(page, '03-phishing-banco');
  await saved(page, 1);
  await home(page);
  await page.getByRole('button', { name: 'Ver historial (1)' }).waitFor();
  await context.close();
});

test('exportar e importar el historial en otra pestaña limpia', { skip }, async () => {
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await withTwo(context, server.url);
  await openView(page);
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Exportar historial (.json)' }).click(),
  ]);
  const dir = mkdtempSync(join(tmpdir(), 'phishlens-'));
  const file = join(dir, 'historial.json');
  await download.saveAs(file);
  const exported = JSON.parse(readFileSync(file, 'utf8'));
  assert.equal(exported.phishlens, 'history/1');
  assert.equal(exported.entries.length, 2);
  assert.ok(!JSON.stringify(exported).includes('Content-Type:'), 'el correo en bruto no se exporta');

  const fresh = await browser.newContext();
  const other = await fresh.newPage();
  other.setDefaultTimeout(8000);
  other.__origin = server.url;
  await home(other);
  await other.locator('#history-toggle').check();
  await analyze(other, '01-legitimo-newsletter');
  await saved(other, 1);
  await home(other);
  await other.getByRole('button', { name: 'Ver historial (1)' }).click();
  await other.locator('#report .history__table').waitFor();
  const bad = join(dir, 'roto.json');
  writeFileSync(bad, JSON.stringify({ phishlens: 'history/1', entries: [...exported.entries, { id: 'x' }] }));
  const [chooser] = await Promise.all([
    other.waitForEvent('filechooser'),
    other.getByRole('button', { name: 'Importar historial (.json)' }).click(),
  ]);
  await chooser.setFiles(bad);
  await other.locator('#report .history__import').waitFor();
  assert.match(await other.locator('#report .history__import').innerText(), /Importados 2; rechazados 1/);
  assert.equal(await other.locator('#report .history__table tbody tr').count(), 3);
  await fresh.close();
  await context.close();
});

for (const colorScheme of ['light', 'dark']) {
  test(`axe: vista «Historial» sin violaciones serias (${colorScheme})`, { skip }, async () => {
    const context = await browser.newContext({ colorScheme });
    const page = await withTwo(context, server.url);
    await openView(page);
    const found = await axe(page);
    await page.getByRole('button', { name: 'Borrar todo' }).click();
    found.push(...(await axe(page)).map((v) => `diálogo: ${v}`));
    assert.deepEqual(found, []);
    await context.close();
  });
}

test('teclado: buscar con Intro, Borrar todo con foco en Cancelar y vuelta al botón', { skip }, async () => {
  const context = await browser.newContext();
  const page = await withTwo(context, server.url);
  await page.locator('#history-open').focus();
  await page.keyboard.press('Enter');
  await page.locator('#report .history__table').waitFor();
  await page.locator('[data-role="history-query"]').focus();
  await page.keyboard.type('correos');
  await page.keyboard.press('Enter');
  await page.locator('#report .history__hits li').first().waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('data-role')), 'history-query');
  await page.locator('#report [data-action="history-clear"]').focus();
  await page.keyboard.press('Enter');
  await page.locator('#report .history__dialog').waitFor();
  const focused = await page.evaluate(() => document.activeElement.textContent);
  assert.equal(focused, 'Cancelar', 'el foco empieza en la acción segura');
  await page.keyboard.press('Enter');
  await page.locator('#report .history__dialog').waitFor({ state: 'hidden' });
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('data-action')), 'history-clear');
  await context.close();
});

for (const width of [360, 768, 1280]) {
  test(`diseño: «Historial» sin scroll horizontal y con objetivos de 44 px a ${width} px`, { skip }, async () => {
    const context = await browser.newContext({ viewport: { width, height: 900 } });
    const page = await withTwo(context, server.url);
    await openView(page);
    assert.ok(await overflow(page) <= 0, `scroll horizontal a ${width} px`);
    const small = await page.evaluate(() => [...document.querySelectorAll('#report .history button, #report .history select, #report .history input[type="search"]')]
      .filter((n) => n.offsetParent && !n.closest('dialog'))
      .map((n) => ({ t: n.textContent || n.getAttribute('data-action'), h: n.getBoundingClientRect().height }))
      .filter((r) => r.h < 44));
    assert.deepEqual(small, []);
    await context.close();
  });
}
