// Panel SOC en un Chromium real (spec 3.0, §3 y §7): privacidad, axe, teclado, «Abrir el último correo»,
// «Activar historial» desde el panel y diseño a 360, 768 y 1280 px.
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

const overflow = (page) => page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
const saved = (page, n) => page.waitForFunction((t) => document.querySelector('#history-open').textContent === t, `Ver historial (${n})`);
const home = (page) => page.goto(`${page.__origin}/index.html`);

async function analyze(page, id) {
  await page.getByRole('button', { name: title(id), exact: true }).click();
  await page.locator('#report .verdict-card, #report .view').first().waitFor();
}

async function toPanel(page) {
  await page.evaluate(() => { location.hash = '#analista/panel'; });
  await page.locator('#report .view--panel').waitFor();
}

/** Historial encendido con tres análisis sueltos y el lote de campaña: 7 guardados y 1 campaña. */
async function withData(page, origin, { lot = true } = {}) {
  page.setDefaultTimeout(8000);
  page.__origin = origin;
  await home(page);
  await page.locator('#history-toggle').check();
  await page.locator('#history-status', { hasText: 'Historial activado.' }).waitFor();
  const ids = ['01-legitimo-newsletter', '03-phishing-banco', '04-phishing-correos'];
  for (const [i, id] of ids.entries()) {
    if (i) await home(page);
    await analyze(page, id);
    await saved(page, i + 1);
  }
  if (lot) {
    await home(page);
    await page.getByRole('button', { name: LOT, exact: true }).click();
    await page.locator('#report .batch-bar').waitFor();
    await saved(page, 7);
  }
  await toPanel(page);
  await page.locator('#report .dashboard__tiles').waitFor();
  return page;
}

const tile = (page, label) => page.locator('#report .stat-tile', { hasText: label }).locator('.stat-tile__value').innerText();

for (const colorScheme of ['light', 'dark']) {
  test(`privacidad: el Panel con datos no hace peticiones ni rompe la CSP (${colorScheme})`, { skip }, async () => {
    const w = await watchedPage(browser, server.url, { colorScheme });
    await withData(w.page, server.url);
    assert.equal(await tile(w.page, 'Análisis guardados'), '7');
    assert.equal(await tile(w.page, 'Campañas'), '1');
    assert.ok(await w.page.locator('#report .chart svg .chart__bar').count() > 0, 'la gráfica de niveles tiene barras');
    assert.deepEqual(w.external, [], 'peticiones fuera del origen');
    assert.deepEqual(await w.violations(), [], 'violaciones de CSP');
    assert.deepEqual(w.errors, [], 'errores de JavaScript');
    await w.context.close();
  });

  test(`axe: Panel sin violaciones serias, apagado y encendido (${colorScheme})`, { skip }, async () => {
    const context = await browser.newContext({ colorScheme });
    const page = await context.newPage();
    page.setDefaultTimeout(8000);
    page.__origin = server.url;
    await home(page);
    await analyze(page, '03-phishing-banco');
    await toPanel(page);
    await page.locator('#report [data-action="history-enable"]').waitFor();
    const found = (await axe(page)).map((v) => `apagado: ${v}`);
    await withData(page, server.url, { lot: true });
    found.push(...(await axe(page)).map((v) => `encendido: ${v}`));
    assert.deepEqual(found, []);
    await context.close();
  });
}

test('teclado: Tab llega a los IOCs, Intro busca en «Historial»; «Abrir el último correo» abre el informe', { skip }, async () => {
  const context = await browser.newContext();
  const page = await withData(await context.newPage(), server.url);
  const iocs = page.locator('#report [data-action="dashboard-search"]');
  const n = await iocs.count();
  assert.ok(n > 0, 'hay IOCs repetidos');
  await page.locator('#report .dashboard').focus().catch(() => {});
  let reached = 0;
  for (let i = 0; i < 80 && reached < n; i++) {
    await page.keyboard.press('Tab');
    if (await page.evaluate(() => document.activeElement?.getAttribute('data-action')) === 'dashboard-search') reached++;
  }
  assert.equal(reached, n, 'Tab recorre todos los botones de IOC');
  const value = await page.evaluate(() => document.activeElement.getAttribute('data-ioc'));
  await page.keyboard.press('Enter');
  await page.locator('#report .history__hits li').first().waitFor();
  assert.equal(await page.locator('[data-role="history-query"]').inputValue(), value);
  assert.match(page.url(), /#analista\/historial$/);

  await toPanel(page);
  await page.locator('#report [data-action="dashboard-open"]').first().click();
  await page.locator('#report .saved-note').waitFor();
  assert.match(await page.locator('#report .saved-note').innerText(), /el correo original no está guardado/);
  await context.close();
});

test('«Activar historial» desde el Panel enciende el interruptor y el Panel pasa a cifras', { skip }, async () => {
  const w = await watchedPage(browser, server.url);
  const { page } = w;
  page.setDefaultTimeout(8000);
  page.__origin = server.url;
  await home(page);
  await analyze(page, '03-phishing-banco');
  await toPanel(page);
  await page.getByRole('button', { name: 'Activar historial' }).click();
  await page.waitForFunction(() => document.querySelector('#history-toggle').checked);
  await home(page);
  await analyze(page, '04-phishing-correos');
  await saved(page, 1);
  await toPanel(page);
  await page.locator('#report .dashboard__tiles').waitFor();
  assert.equal(await tile(page, 'Análisis guardados'), '1');
  assert.deepEqual(w.errors, []);
  await w.context.close();
});

for (const width of [360, 768, 1280]) {
  test(`diseño: Panel sin scroll horizontal, objetivos de 44 px y SVG dentro de su caja a ${width} px`, { skip }, async () => {
    const context = await browser.newContext({ viewport: { width, height: 900 } });
    const page = await withData(await context.newPage(), server.url);
    assert.ok(await overflow(page) <= 0, `scroll horizontal a ${width} px`);
    const problems = await page.evaluate(() => {
      const out = [];
      for (const b of document.querySelectorAll('#report .dashboard button')) {
        const r = b.getBoundingClientRect();
        if (b.offsetParent && r.height < 44) out.push(`botón bajo: ${b.textContent.slice(0, 30)} ${r.height}`);
      }
      for (const svg of document.querySelectorAll('#report .dashboard svg')) {
        const s = svg.getBoundingClientRect();
        const box = svg.closest('.card').getBoundingClientRect();
        if (s.left < box.left - 0.5 || s.right > box.right + 0.5) out.push(`SVG fuera de su tarjeta: ${s.left}-${s.right} en ${box.left}-${box.right}`);
      }
      return out;
    });
    assert.deepEqual(problems, []);
    await context.close();
  });
}
