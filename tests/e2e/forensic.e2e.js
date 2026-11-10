// Informe forense en un Chromium real (spec 3.0, §4 y §7): el PDF lleva el SHA-256 del .eml, el JSON se
// verifica, las notas se guardan con el historial, el diálogo se usa con teclado y nada sale del navegador.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { serve } from './server.js';
import { openBrowser, watchedPage } from './browser.js';
import { SAMPLES } from '../../samples/index.js';
import { verifyForensicJson } from '../../src/intel/forensic.js';

const AXE = process.env.AXE_PATH ?? fileURLToPath(new URL('../../node_modules/axe-core/axe.min.js', import.meta.url));
const noAxe = existsSync(AXE) ? false : `axe-core no está en ${AXE} (npm ci o AXE_PATH)`;
if (noAxe && process.env.CI) throw new Error(noAxe);
const { browser, skip: noBrowser } = noAxe ? {} : await openBrowser();
const skip = noAxe || noBrowser || false;
const title = (id) => SAMPLES.find((s) => s.id === id).title;
const SHA_03 = createHash('sha256').update(readFileSync(new URL('../../samples/03-phishing-banco.eml', import.meta.url))).digest('hex');
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

async function open(page, id = '03-phishing-banco', hash = '#analista') {
  page.setDefaultTimeout(8000);
  await page.goto(`${server.url}/index.html${hash}`);
  await page.getByRole('button', { name: title(id), exact: true }).click();
  await page.locator('#report .report__toolbar').waitFor();
}

async function openDialog(page) {
  await page.getByRole('button', { name: 'Exportar' }).click();
  await page.getByRole('menuitem', { name: 'Informe forense' }).click();
  await page.locator('dialog.forensic-dialog[open]').waitFor();
}

const pdftotext = (() => {
  try { execFileSync('pdftotext', ['-v'], { stdio: 'ignore' }); return true; } catch { return false; }
})();

test('PDF: page.pdf() del informe tiene varias páginas y lleva el SHA-256 del .eml y «Página 2»', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await open(page);
  await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
  await page.emulateMedia({ media: 'print' });
  const footer = page.locator('#report .forensic__footer');
  assert.equal(await footer.innerText(), `SHA-256 ${SHA_03}`);
  assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--forensic-sha').trim()), `"${SHA_03}"`, 'el pie de cada hoja');
  const pdf = await page.pdf({ format: 'A4' });
  const pages = (pdf.toString('latin1').match(/\/Type\s*\/Page[^s]/g) ?? []).length;
  assert.ok(pages >= 2, `${pages} páginas`);
  if (pdftotext) {
    const dir = mkdtempSync(join(tmpdir(), 'phishlens-pdf-'));
    writeFileSync(join(dir, 'i.pdf'), pdf);
    const text = execFileSync('pdftotext', ['-layout', join(dir, 'i.pdf'), '-'], { encoding: 'utf8' });
    assert.ok(text.includes(SHA_03), 'el SHA-256 está en el texto del PDF');
    assert.match(text, /Página 2/);
    assert.ok(text.split('\f').filter((p) => p.includes(`SHA-256 ${SHA_03}`)).length >= 2, 'el pie va en cada hoja');
  }
  await context.close();
});

for (const [colorScheme, width] of [['dark', 1280], ['light', 390]]) {
  test(`Review Focus 5: impreso en ${colorScheme} a ${width} px: fondo blanco, gravedad en texto y filas que no se parten`, { skip }, async () => {
    const context = await browser.newContext({ colorScheme, viewport: { width, height: 900 } });
    const page = await context.newPage();
    await open(page, '12-pdf-activo-zip');
    await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
    await page.emulateMedia({ media: 'print', colorScheme });
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgb(255, 255, 255)');
    const sev = await page.locator('#report .forensic .sev').allInnerTexts();
    assert.ok(sev.length > 0 && sev.every((t) => /^(GRAVE|MEDIA|LEVE|INFO)$/.test(t)), sev.join(','));
    assert.deepEqual(await page.locator('#report .forensic tr').evaluateAll((rows) => [...new Set(rows.map((r) => getComputedStyle(r).breakInside))]), ['avoid']);
    assert.deepEqual(await page.locator('#report .forensic thead').evaluateAll((h) => [...new Set(h.map((x) => getComputedStyle(x).display))]), ['table-header-group']);
    await context.close();
  });
}

test('JSON: se llama phishlens-forense-AAAA-MM-DD.json y verifyForensicJson lo acepta', { skip }, async () => {
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  await open(page);
  await openDialog(page);
  await page.locator('[data-role="forensic-notes"]').fill('Lo reenvió contabilidad.');
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Descargar JSON' }).click()]);
  assert.match(download.suggestedFilename(), /^phishlens-forense-\d{4}-\d\d-\d\d\.json$/);
  const file = join(mkdtempSync(join(tmpdir(), 'phishlens-')), 'f.json');
  await download.saveAs(file);
  const text = readFileSync(file, 'utf8');
  assert.equal(verifyForensicJson(text), true);
  const doc = JSON.parse(text);
  assert.equal(doc.identification.sha256, SHA_03);
  assert.equal(doc.notes, 'Lo reenvió contabilidad.');
  await context.close();
});

test('notas: con el historial encendido se guardan y vuelven al abrir la entrada desde «Historial»', { skip }, async () => {
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  page.setDefaultTimeout(8000);
  await page.goto(`${server.url}/index.html`);
  await page.locator('#history-toggle').check();
  await page.locator('#history-status', { hasText: 'Historial activado.' }).waitFor();
  await page.getByRole('button', { name: title('03-phishing-banco'), exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#history-open').textContent === 'Ver historial (1)');
  await openDialog(page);
  await page.locator('[data-role="forensic-notes"]').fill('Caso 2026-118');
  await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Descargar JSON' }).click()]);
  await page.reload();
  await page.getByRole('button', { name: 'Ver historial (1)' }).click();
  await page.locator('#report [data-action="history-open"]').first().click();
  await page.locator('#report .saved-note').waitFor();
  await openDialog(page);
  assert.equal(await page.locator('[data-role="forensic-notes"]').inputValue(), 'Caso 2026-118');
  assert.equal(await page.locator('[data-role="forensic-count"]').innerText(), '13 de 5.000');
  await context.close();
});

for (const colorScheme of ['light', 'dark']) {
  test(`diálogo: axe sin problemas serios (${colorScheme})`, { skip }, async () => {
    const context = await browser.newContext({ colorScheme });
    const page = await context.newPage();
    await open(page);
    await openDialog(page);
    assert.deepEqual(await axe(page), []);
    await context.close();
  });
}

test('teclado: el foco empieza en las notas, Tab recorre las acciones y Escape vuelve a Exportar', { skip }, async () => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await open(page);
  const trigger = page.locator('#report [aria-haspopup="menu"]');
  await trigger.focus();
  await page.keyboard.press('Enter');
  for (let i = 0; i < 3; i++) await page.keyboard.press('ArrowDown');
  assert.equal(await page.evaluate(() => document.activeElement.textContent), 'Informe forense');
  await page.keyboard.press('Enter');
  await page.locator('dialog.forensic-dialog[open]').waitFor();
  const active = () => page.evaluate(() => document.activeElement.getAttribute('data-role') ?? document.activeElement.textContent);
  assert.equal(await active(), 'forensic-notes');
  const seen = [];
  for (let i = 0; i < 3; i++) {
    await page.keyboard.press('Tab');
    seen.push(await active());
  }
  assert.deepEqual(seen, ['Guardar como PDF', 'Descargar JSON', 'Cerrar']);
  await page.keyboard.press('Escape');
  await page.locator('dialog.forensic-dialog').waitFor({ state: 'detached' });
  assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-haspopup')), 'menu');
  await context.close();
});

test('privacidad: diálogo, impresión y JSON sin peticiones externas ni violaciones de CSP', { skip }, async () => {
  const w = await watchedPage(browser, server.url);
  w.page.setDefaultTimeout(8000);
  await w.page.goto(`${server.url}/index.html#analista`);
  await w.page.getByRole('button', { name: title('03-phishing-banco'), exact: true }).click();
  await w.page.locator('#report .report__toolbar').waitFor();
  await openDialog(w.page);
  await w.page.locator('[data-role="forensic-notes"]').fill('<img src="https://evil.test/x.png">');
  await w.page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
  await w.page.emulateMedia({ media: 'print' });
  await w.page.pdf();
  assert.equal(await w.page.locator('#report .forensic img').count(), 0);
  assert.deepEqual(w.external, [], 'peticiones fuera del origen');
  assert.deepEqual(await w.violations(), [], 'violaciones de CSP');
  assert.deepEqual(w.errors, [], 'errores de JavaScript');
  await w.context.close();
});
