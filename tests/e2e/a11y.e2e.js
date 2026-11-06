// Accesibilidad en un Chromium real: axe-core sin violaciones serias ni críticas, y todo usable con teclado.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { serve } from './server.js';
import { openBrowser } from './browser.js';
import { SAMPLES } from '../../samples/index.js';

const AXE = process.env.AXE_PATH ?? fileURLToPath(new URL('../../node_modules/axe-core/axe.min.js', import.meta.url));
const noAxe = existsSync(AXE) ? false : `axe-core no está en ${AXE} (npm ci o AXE_PATH)`;
if (noAxe && process.env.CI) throw new Error(noAxe);
const { browser, skip: noBrowser } = noAxe ? {} : await openBrowser();
const skip = noAxe || noBrowser || false;
const REPORTS = ['01-legitimo-newsletter', '03-phishing-banco', '06-phishing-factura-adjunto'];
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
  return violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
}

test('control negativo: axe ve los fallos de una página mal hecha', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${server.url}/tests/fixtures/a11y/bad.html`);
  const found = (await axe(page)).join('\n');
  assert.match(found, /button-name/);
  assert.match(found, /color-contrast/);
  await context.close();
});

const title = (id) => SAMPLES.find((s) => s.id === id).title;

for (const colorScheme of ['light', 'dark']) {
  test(`axe: portada e informes sin violaciones serias (${colorScheme})`, { skip }, async () => {
    const context = await browser.newContext({ colorScheme });
    const page = await context.newPage();
    page.setDefaultTimeout(5000);
    await page.goto(`${server.url}/index.html`);
    const found = (await axe(page)).map((v) => `portada: ${v}`);
    for (const id of REPORTS) {
      await page.getByRole('button', { name: title(id), exact: true }).click();
      await page.locator('#report .verdict-card').waitFor();
      found.push(...(await axe(page)).map((v) => `${id} / sencillo: ${v}`));
      await page.locator('#report [data-action="mode-analyst"]').first().click();
      const links = page.locator('#report nav a');
      await links.first().waitFor();
      for (let i = 0; i < await links.count(); i++) {
        await links.nth(i).click();
        await page.locator('#report nav a[aria-current="page"]').nth(0).waitFor();
        const name = await links.nth(i).textContent();
        found.push(...(await axe(page)).map((v) => `${id} / ${name}: ${v}`));
      }
      await page.locator('#report [data-action="mode-simple"]').click();
    }
    assert.deepEqual([...new Set(found)], []);
    await context.close();
  });
}

test('teclado: cargar una muestra, pasar al modo analista, cambiar de vista y abrir «¿Por qué?»', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  await page.goto(`${server.url}/index.html`);
  const active = () => page.evaluate(() => {
    const a = document.activeElement;
    return { text: a?.textContent?.trim() ?? '', tag: a?.tagName, role: a?.getAttribute('role'), id: a?.id, href: a?.getAttribute('href') };
  });
  const tabUntil = async (pred, what, max = 80) => {
    for (let i = 0; i < max; i++) {
      await page.keyboard.press('Tab');
      if (pred(await active())) return;
    }
    assert.fail(`con Tab no se llega a ${what}`);
  };

  await tabUntil((a) => a.text === title('03-phishing-banco'), 'la muestra 03');
  await page.keyboard.press('Enter');
  await page.locator('#report .verdict-card').waitFor();
  // El lector de pantalla oye un aviso corto, no el informe entero.
  await page.waitForFunction(() => document.querySelector('#report-status')?.textContent.includes('No te fíes: es phishing'));

  await tabUntil((a) => a.text === 'Ver todos los detalles (modo analista)', 'el botón del modo analista');
  await page.keyboard.press('Enter');
  await page.locator('#report nav').waitFor();
  assert.equal(new URL(page.url()).hash, '#analista');
  assert.equal((await active()).tag, 'H2', 'el foco no va al título de la vista');

  await tabUntil((a) => a.href === '#analista/autenticacion', 'el enlace «Autenticación»');
  await page.keyboard.press('Enter');
  await page.locator('#report .view--autenticacion').waitFor();
  assert.equal((await active()).text, 'Autenticación');
  assert.equal(await page.locator('#report nav a[aria-current="page"]').getAttribute('href'), '#analista/autenticacion');

  // Menú Exportar solo con teclado: Shift+Tab hasta el botón, Enter abre, flecha baja, Escape vuelve al botón.
  for (let i = 0; i < 40 && (await page.evaluate(() => document.activeElement?.getAttribute('aria-haspopup'))) !== 'menu'; i++) {
    await page.keyboard.press('Shift+Tab');
  }
  await page.keyboard.press('Enter');
  assert.equal((await active()).text, 'Descargar informe (JSON)');
  await page.keyboard.press('ArrowDown');
  assert.equal((await active()).text, 'Copiar IOCs');
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('aria-haspopup')), 'menu');

  // Atrás del navegador vuelve a la vista anterior.
  await page.goBack();
  await page.locator('#report .view--resumen').waitFor();

  await tabUntil((a) => a.tag === 'SUMMARY' && a.text === '¿Por qué?', '«¿Por qué?»');
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('summary:has-text("¿Por qué?")').locator('..').getAttribute('open'), '');
  await context.close();
});

async function openReport(id, { colorScheme = 'light', width = 1280 } = {}) {
  const context = await browser.newContext({ colorScheme, viewport: { width, height: 900 } });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  await page.goto(`${server.url}/index.html#analista`);
  await page.getByRole('button', { name: title(id), exact: true }).click();
  await page.locator('#report nav a').first().waitFor();
  return { page, context };
}

test('categorías: la etiqueta nunca se corta y la cifra se lee «x de y»', { skip }, async () => {
  for (const width of [360, 1280]) {
    const { page, context } = await openReport('03-phishing-banco', { width });
    const labels = await page.locator('.meter__label').evaluateAll((els) => els.map((e) => ({ t: e.textContent, cut: e.scrollWidth > e.clientWidth })));
    assert.deepEqual(labels.filter((l) => l.cut), [], `ancho ${width}`);
    const aria = await page.locator('.meter__value').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label')));
    for (const a of aria) assert.match(a ?? '', /^\d+(,\d)? de \d+$/);
    await context.close();
  }
});

test('nota 0: el motivo principal no repite el resumen', { skip }, async () => {
  const { page, context } = await openReport('01-legitimo-newsletter');
  assert.equal(await page.locator('.report__reason').count(), 0);
  assert.equal(await page.locator('.report__summary').count(), 1);
  await context.close();
});

test('impresión: los «¿Por qué?» se abren y el informe sale en claro aunque esté en oscuro', { skip }, async () => {
  const { page, context } = await openReport('03-phishing-banco', { colorScheme: 'dark' });
  await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
  assert.deepEqual(await page.locator('#report details:not(.auth-local)').evaluateAll((els) => els.filter((d) => !d.open).length), 0);
  await page.emulateMedia({ media: 'print', colorScheme: 'dark' });
  const bg = await page.locator('#report .card').first().evaluate((e) => getComputedStyle(e).backgroundColor);
  assert.equal(bg, 'rgb(255, 255, 255)');
  await page.evaluate(() => window.dispatchEvent(new Event('afterprint')));
  assert.ok(await page.locator('#report details').evaluateAll((els) => els.some((d) => !d.open)), 'tras imprimir vuelven a cerrarse');
  await context.close();
});

test('menú Exportar: se abre con teclado, las flechas se mueven y Escape vuelve al botón', { skip }, async () => {
  const { page, context } = await openReport('03-phishing-banco');
  const trigger = page.locator('#report [aria-haspopup="menu"]');
  await trigger.focus();
  await page.keyboard.press('Enter');
  assert.equal(await trigger.getAttribute('aria-expanded'), 'true');
  const focused = () => page.evaluate(() => document.activeElement?.textContent);
  assert.equal(await focused(), 'Descargar informe (JSON)');
  await page.keyboard.press('ArrowDown');
  assert.equal(await focused(), 'Copiar IOCs');
  await page.keyboard.press('ArrowUp');
  await page.keyboard.press('ArrowUp');
  assert.equal(await focused(), 'Imprimir');
  await page.keyboard.press('Escape');
  assert.equal(await trigger.getAttribute('aria-expanded'), 'false');
  assert.equal(await page.locator('#report [role="menu"]').isHidden(), true);
  assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('aria-haspopup')), 'menu');
  // Un clic fuera también lo cierra.
  await trigger.click();
  assert.equal(await trigger.getAttribute('aria-expanded'), 'true');
  await page.locator('#report .view__title').click();
  assert.equal(await trigger.getAttribute('aria-expanded'), 'false');
  await context.close();
});
