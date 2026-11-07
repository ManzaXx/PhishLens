// Lotes, grafo y campañas en un Chromium real (spec 2.3, §5.2 y §7): privacidad, axe, teclado y diseño.
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
const TEN = SAMPLES.slice(0, 10).map((s) => fileURLToPath(new URL(`../../samples/${s.file}`, import.meta.url)));
const LOT = 'Lote de campaña (4 correos)';
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

async function loadLot(page) {
  await page.getByRole('button', { name: LOT, exact: true }).click();
  await page.locator('#report .batch-bar').waitFor();
}

for (const colorScheme of ['light', 'dark']) {
  test(`privacidad: un lote de 10 correos por todas las vistas sin peticiones externas (${colorScheme})`, { skip }, async () => {
    const w = await watchedPage(browser, server.url, { colorScheme });
    w.page.setDefaultTimeout(8000);
    await w.page.goto(`${server.url}/index.html`);
    await w.page.setInputFiles('#file-input', TEN);
    await w.page.locator('#report .batch-bar').waitFor();
    assert.equal(await w.page.locator('#batch-email option').count(), 10);
    for (const index of [0, 5, 9]) {
      await w.page.selectOption('#batch-email', { index });
      await w.page.locator('#report [data-action="mode-analyst"]').first().click();
      const links = w.page.locator('#report nav a');
      await links.first().waitFor();
      for (let i = 0; i < await links.count(); i++) {
        await links.nth(i).click();
        await w.page.waitForTimeout(30);
      }
      await w.page.locator('#report [data-action="mode-simple"]').click();
    }
    await w.page.waitForTimeout(200);
    assert.deepEqual(w.external, [], 'peticiones fuera del origen');
    assert.deepEqual(await w.violations(), [], 'violaciones de CSP');
    assert.deepEqual(w.errors, [], 'errores de JavaScript');
    await w.context.close();
  });

  test(`axe: lote, «IOCs» y «Campañas» sin violaciones serias (${colorScheme})`, { skip }, async () => {
    const context = await browser.newContext({ colorScheme });
    const page = await context.newPage();
    page.setDefaultTimeout(5000);
    await page.goto(`${server.url}/index.html`);
    await loadLot(page);
    const found = (await axe(page)).map((v) => `sencillo: ${v}`);
    for (const view of ['iocs', 'campanas']) {
      await page.goto(`${server.url}/index.html#analista/${view}`);
      await loadLot(page);
      await page.locator(`#report .view--${view}`).waitFor();
      found.push(...(await axe(page)).map((v) => `${view}: ${v}`));
    }
    assert.deepEqual([...new Set(found)], []);
    await context.close();
  });
}

test('teclado: el grafo es un solo paso de Tab, las flechas lo recorren y resaltan las relaciones', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  await page.goto(`${server.url}/index.html#analista/iocs`);
  await loadLot(page);
  const first = page.locator('.graph__node[tabindex="0"]');
  await first.focus();
  const name1 = await page.evaluate(() => document.activeElement.getAttribute('aria-label'));
  await page.keyboard.press('ArrowRight');
  const state = await page.evaluate(() => ({
    name: document.activeElement.getAttribute('aria-label'),
    tabbable: document.querySelectorAll('.graph__node[tabindex="0"]').length,
    related: document.querySelectorAll('.graph__node.is-related').length,
    focusedRelated: document.activeElement.classList.contains('is-related'),
  }));
  assert.notEqual(state.name, name1);
  assert.equal(state.tabbable, 1);
  assert.ok(state.related >= 2 && state.focusedRelated, JSON.stringify(state));
  await page.keyboard.press('End');
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => Boolean(document.activeElement.closest('.graph__svg'))), false, 'Tab sale del grafo');
  await context.close();
});

test('teclado: elegir la campaña y abrir uno de sus correos lleva el foco al resumen', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  await page.goto(`${server.url}/index.html`);
  await loadLot(page);
  await page.locator('[data-action="view-campaign"]').focus();
  await page.keyboard.press('Enter');
  await page.locator('#report .campaign__title').waitFor();
  await page.locator('#report [data-action="pick-campaign"]').focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.evaluate(() => document.activeElement.className), 'campaign__title');
  const target = page.locator('#report .campaign__email').nth(2);
  const key = await target.getAttribute('data-key');
  await target.focus();
  await page.keyboard.press('Enter');
  await page.locator('#report .view--resumen').waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Resumen');
  assert.equal(await page.inputValue('#batch-email'), key);
  await context.close();
});

test('a 360 px: sin scroll horizontal y objetivos de 44 px en el lote, «IOCs» y «Campañas»', { skip }, async () => {
  const context = await browser.newContext({ viewport: { width: 360, height: 800 } });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const problems = [];
  for (const hash of ['', '#analista/iocs', '#analista/campanas']) {
    await page.goto(`${server.url}/index.html${hash}`);
    await loadLot(page);
    if (await overflow(page) > 0) problems.push(`${hash || 'sencillo'}: scroll horizontal`);
    const small = await page.evaluate(() => [...document.querySelectorAll('#batch-email, #report .campaign-list__btn, #report .campaign__email, #report .campaign-note .btn')]
      .filter((n) => n.getBoundingClientRect().height < 44 || n.getBoundingClientRect().width < 44)
      .map((n) => `${n.className} ${Math.round(n.getBoundingClientRect().height)}`));
    problems.push(...small.map((s) => `${hash || 'sencillo'}: ${s}`));
  }
  assert.deepEqual(problems, []);
  await context.close();
});

test('un análisis nuevo descarta el lote que sigue en marcha', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  await page.goto(`${server.url}/index.html`);
  await page.setInputFiles('#file-input', TEN);
  await page.getByRole('button', { name: SAMPLES[2].title, exact: true }).click();
  await page.locator('#report .verdict-card').waitFor();
  await page.waitForTimeout(1500);
  assert.equal(await page.locator('#report .batch-bar').count(), 0, 'el lote viejo pintó encima');
  assert.equal(await page.locator('#batch-status').isHidden(), true);
  await context.close();
});

test('lector de pantalla: el estado del lote no se anuncia en cada correo y dice qué se ha saltado', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  await page.goto(`${server.url}/index.html`);
  await page.evaluate(() => {
    window.statusTexts = [];
    const box = document.querySelector('#batch-progress-text');
    new MutationObserver(() => window.statusTexts.push(box.textContent)).observe(box, { childList: true, characterData: true, subtree: true });
  });
  await page.setInputFiles('#file-input', [...TEN, fileURLToPath(new URL('../../README.md', import.meta.url))]);
  await page.locator('#report .batch-bar').waitFor();
  const texts = [...new Set(await page.evaluate(() => window.statusTexts))];
  assert.ok(texts.length <= 4, texts.join(' | '));
  assert.equal(texts.at(-1), '10 correos analizados. Un archivo no se ha analizado.');
  await context.close();
});

test('el lote sobrevive a un «Analizar» sin datos nuevos y no vuelve a un correo anterior', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  await page.goto(`${server.url}/index.html#analista/campanas`);
  await page.setInputFiles('#file-input', TEN[0]);
  await page.locator('#report .verdict-card, #report nav').first().waitFor();
  await loadLot(page);
  // Pestaña .eml sin fichero nuevo: «Analizar» no rehace el correo suelto de antes.
  await page.locator('#analyze-btn').click();
  assert.equal(await page.locator('#report .batch-bar').count(), 1, 'el lote desaparece con «Analizar»');
  assert.equal(await page.locator('#batch-email option').count(), 4);
  // Pestaña URL vacía + Enter: error, pero el lote sigue ahí y se puede cambiar de correo.
  await page.locator('#tab-url').click();
  await page.locator('#url-input').press('Enter');
  assert.equal(await page.locator('#input-error').isVisible(), true);
  assert.equal(await page.locator('#report .batch-bar').count(), 1, 'el lote desaparece con una URL vacía');
  await page.selectOption('#batch-email', { index: 2 });
  await page.locator('#report nav a[href="#analista/campanas"]').waitFor();
  // Elegir un fichero que no vale no descarta el lote ni deja el texto del lote en la zona de arrastre.
  await page.locator('#tab-eml').click();
  await page.setInputFiles('#file-input', fileURLToPath(new URL('../../README.md', import.meta.url)));
  assert.equal(await page.locator('#report .batch-bar').count(), 1, 'un fichero no válido descarta el lote');
  await page.getByRole('button', { name: SAMPLES[2].title, exact: true }).click();
  await page.locator('#report .batch-bar').waitFor({ state: 'detached' });
  assert.equal(/correos/.test(await page.locator('.dropzone__title').textContent()), false, 'la zona de arrastre sigue hablando del lote');
  await context.close();
});

test('el foco se ve en todos los tipos de nodo, también en las IP', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  await page.goto(`${server.url}/index.html#analista/iocs`);
  await loadLot(page);
  await page.locator('.graph__node[tabindex="0"]').focus();
  const seen = new Map();
  for (let i = 0; i < 60; i++) {
    await page.keyboard.press('ArrowRight');
    const s = await page.evaluate(() => {
      const n = document.activeElement;
      const shape = n.querySelector('.graph__shape');
      const cs = getComputedStyle(shape);
      return { type: [...n.classList].find((c) => c.startsWith('graph__node--')), fill: cs.fill, stroke: cs.stroke };
    });
    if (!seen.has(s.type)) seen.set(s.type, s);
  }
  assert.ok(seen.has('graph__node--ip'), `sin nodos IP: ${[...seen.keys()]}`);
  for (const [type, s] of seen) assert.notEqual(s.stroke, s.fill, `${type}: el anillo de foco tiene el color del relleno`);
  await context.close();
});
