// Diseño adaptable (spec 2.3, §4): sin scroll horizontal, objetivos táctiles de 44 px y navegación en una fila.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from './server.js';
import { openBrowser } from './browser.js';
import { SAMPLES } from '../../samples/index.js';
import { DEFAULT_DETECTORS } from '../../src/core/engine.js';

const { browser, skip } = await openBrowser();
const WIDTHS = [360, 768, 1280];
const IDS = ['01-legitimo-newsletter', '03-phishing-banco', '07-phishing-avanzado', '12-pdf-activo-zip'];
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

/** Controles visibles más pequeños de 44×44 (los enlaces dentro de un texto no cuentan). */
const smallTargets = (page) => page.evaluate(() => {
  const nodes = document.querySelectorAll('.topbar a, .topbar button, #report button, #report a, #report [role="menuitem"]');
  return [...nodes].filter((n) => {
    const r = n.getBoundingClientRect();
    if (!r.width || !r.height || n.closest('[hidden]')) return false;
    if (n.tagName === 'A' && n.closest('p, li:not(.nav-rail li), td, dd')) return false;
    return r.width < 44 || r.height < 44;
  }).map((n) => `${n.tagName.toLowerCase()} «${n.textContent.trim().slice(0, 30)}» ${Math.round(n.getBoundingClientRect().width)}×${Math.round(n.getBoundingClientRect().height)}`);
});

const overflow = (page) => page.evaluate(() => document.documentElement.scrollWidth - innerWidth);

for (const width of WIDTHS) {
  test(`a ${width} px: sin scroll horizontal, objetivos de 44 px y navegación ordenada`, { skip }, async () => {
    const context = await browser.newContext({ viewport: { width, height: 900 } });
    const page = await context.newPage();
    page.setDefaultTimeout(5000);
    await page.goto(`${server.url}/index.html`);
    assert.equal(await overflow(page), 0, 'portada');
    assert.equal(await page.locator('[data-fact="detectors"]').textContent(), String(DEFAULT_DETECTORS.length));
    const problems = [];
    for (const id of IDS) {
      await page.getByRole('button', { name: title(id), exact: true }).click();
      await page.locator('#report .verdict-card').waitFor();
      if (await overflow(page) > 0) problems.push(`${id} sencillo: scroll horizontal`);
      problems.push(...(await smallTargets(page)).map((t) => `${id} sencillo: ${t}`));

      await page.locator('#report [data-action="mode-analyst"]').first().click();
      const links = page.locator('#report nav a');
      await links.first().waitFor();
      for (let i = 0; i < await links.count(); i++) {
        await links.nth(i).click();
        await page.waitForTimeout(20);
        const view = await links.nth(i).getAttribute('href');
        if (await overflow(page) > 0) problems.push(`${id} ${view}: scroll horizontal`);
        problems.push(...(await smallTargets(page)).map((t) => `${id} ${view}: ${t}`));
      }
      const nav = await page.locator('#report nav').boundingBox();
      if (width < 900 && nav.height > 60) problems.push(`${id}: la navegación ocupa ${Math.round(nav.height)} px de alto`);
      if (width >= 900 && nav.height < nav.width) problems.push(`${id}: la navegación no es una columna`);

      await page.locator('#report [aria-haspopup="menu"]').click();
      problems.push(...(await smallTargets(page)).map((t) => `${id} menú: ${t}`));
      await page.keyboard.press('Escape');
      await page.locator('#report [data-action="mode-simple"]').click();
    }
    assert.deepEqual([...new Set(problems)], []);
    await context.close();
  });
}

test('a 360 px: la vista actual se ve en la barra de navegación y el veredicto no deja el icono solo', { skip }, async () => {
  const context = await browser.newContext({ viewport: { width: 360, height: 800 } });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  await page.goto(`${server.url}/index.html#analista/attack`);
  await page.getByRole('button', { name: title('03-phishing-banco'), exact: true }).click();
  const current = await page.locator('#report nav a[aria-current="page"]').boundingBox();
  const nav = await page.locator('#report nav').boundingBox();
  assert.ok(current.x >= nav.x - 1 && current.x + current.width <= nav.x + nav.width + 1, `ATT&CK fuera de la vista: ${JSON.stringify({ current, nav })}`);

  await page.locator('#report [data-action="mode-simple"]').click();
  const icon = await page.locator('#report .verdict-card .icon').boundingBox();
  const headline = await page.locator('#report .verdict-card__headline').boundingBox();
  assert.ok(icon.y < headline.y + headline.height && headline.y < icon.y + icon.height, 'el icono queda en otra fila que el titular');
  await context.close();
});
