// Capturas de docs/img para el README. Se ejecuta a mano (no es un test): node tools/screenshots.mjs
// Con --lang en salen en inglés y van a docs/img/en/: node tools/screenshots.mjs --lang en
// Usa el Chromium de Playwright y el servidor estático de los e2e; reduce el movimiento para que
// el anillo salga con su nota final.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { serve } from '../tests/e2e/server.js';
import { SAMPLES, BATCHES } from '../samples/index.js';
import ES from '../src/i18n/es.js';
import EN from '../src/i18n/en.js';

const { chromium } = createRequire(import.meta.url)('playwright');
const args = process.argv.slice(2);
const at = args.indexOf('--lang');
const LANG = at !== -1 && args[at + 1] === 'en' ? 'en' : 'es';
if (at !== -1) args.splice(at, 2);
const OUT = fileURLToPath(new URL(LANG === 'en' ? '../docs/img/en/' : '../docs/img/', import.meta.url));
const LOCALE = LANG === 'en' ? 'en-GB' : 'es-ES';
// Textos de la interfaz en el idioma de las capturas, sacados de los diccionarios.
const tx = (key, params = {}) => (LANG === 'en' ? EN : ES)[key].replace(/\{(\w+)\}/g, (all, k) => String(params[k] ?? all));
const NOTES = LANG === 'en'
  ? 'Received by three people in Accounting. Sender blocked at the gateway.'
  : 'Recibido por tres personas de Administración. Bloqueado el remitente en la pasarela.';
const pick = (item) => (LANG === 'en' ? item.titleEn : item.title);
const title = (id) => pick(id === 'lote' ? BATCHES[0] : SAMPLES.find((s) => s.id === id));

// [archivo, muestra ('lote' = el lote de campaña; 'historial' = tres análisis guardados; 'panel' = tres sueltos y el lote)
// o null (portada), hash, ancho, tema]
// Con argumentos solo se hacen esas capturas: node tools/screenshots.mjs analista-grafo movil-lote
const SHOTS = [
  ['inicio', null, '', 1280, 'light'],
  ['sencillo-claro', '03-phishing-banco', '', 1280, 'light'],
  ['sencillo-oscuro', '03-phishing-banco', '', 1280, 'dark'],
  ['sencillo-legitimo', '02-legitimo-pedido', '', 1280, 'light'],
  ['analista-resumen', '07-phishing-avanzado', '#analista', 1280, 'dark'],
  ['analista-senales', '03-phishing-banco', '#analista/senales', 1280, 'light'],
  ['analista-autenticacion', '03-phishing-banco', '#analista/autenticacion', 1280, 'light'],
  ['analista-cabeceras', '08-ruta-falsificada', '#analista/cabeceras', 1280, 'light'],
  ['analista-vista-segura', '07-phishing-avanzado', '#analista/vista-segura', 1280, 'light'],
  ['analista-adjuntos', '12-pdf-activo-zip', '#analista/adjuntos', 1280, 'light'],
  ['analista-urls', '13-redireccion-anidada', '#analista/urls', 1280, 'light'],
  ['analista-iocs', '10-dominio-unicode', '#analista/iocs', 1280, 'dark'],
  ['analista-attack', '03-phishing-banco', '#analista/attack', 1280, 'light'],
  ['analista-grafo', 'lote', '#analista/iocs', 1280, 'light'],
  ['analista-campanas', 'lote', '#analista/campanas', 1280, 'dark'],
  ['analista-historial', 'historial', '', 1280, 'light'],
  ['movil-historial', 'historial', '', 390, 'dark'],
  ['analista-panel', 'panel', '', 1280, 'light'],
  ['informe-forense', 'forense', '#analista', 900, 'light'],
  ['forense-dialogo', 'forense-dialogo', '#analista', 390, 'dark'],
  ['reglas-vista-previa', 'reglas', '', 1280, 'light'],
  ['movil-reglas', 'reglas', '', 390, 'dark'],
  ['movil-panel', 'panel', '', 390, 'dark'],
  ['movil-lote', 'lote', '', 390, 'light'],
  ['movil-sencillo', '03-phishing-banco', '', 390, 'light'],
  ['movil-analista', '03-phishing-banco', '#analista/senales', 390, 'dark'],
];

/** Enciende el historial, guarda tres análisis y abre la vista con dos marcados y comparados. */
async function savedHistory(page) {
  await page.locator('#history-toggle').check();
  for (const [i, id] of ['03-phishing-banco', '04-phishing-correos', '02-legitimo-pedido'].entries()) {
    await page.getByRole('button', { name: title(id), exact: true }).click();
    await page.waitForFunction((t) => document.querySelector('#history-open').textContent === t, tx('app.history.open', { n: i + 1 }));
    await page.goto(`${server.url}/index.html`);
  }
  await page.locator('#history-open').click();
  await page.locator('#report .history__table').waitFor();
  const boxes = page.locator('#report [data-action="history-select"]');
  await boxes.nth(1).check();
  await boxes.nth(2).check();
  await page.getByRole('button', { name: tx('history.compare.two') }).click();
  await page.locator('#report .history__compare').waitFor();
  await page.locator('#report').evaluate((n) => n.scrollIntoView({ block: 'start' }));
}

/** Enciende el historial, guarda tres análisis sueltos y el lote de campaña, y abre el Panel. */
async function savedPanel(page) {
  await page.locator('#history-toggle').check();
  const wait = (n) => page.waitForFunction((t) => document.querySelector('#history-open').textContent === t, tx('app.history.open', { n }));
  for (const [i, id] of ['03-phishing-banco', '04-phishing-correos', '02-legitimo-pedido'].entries()) {
    await page.getByRole('button', { name: title(id), exact: true }).click();
    await wait(i + 1);
    await page.goto(`${server.url}/index.html`);
  }
  await page.getByRole('button', { name: title('lote'), exact: true }).click();
  await wait(7);
  await page.evaluate(() => { location.hash = '#analista/panel'; });
  await page.locator('#report .dashboard__tiles').waitFor();
  await page.locator('#report').evaluate((n) => n.scrollIntoView({ block: 'start' }));
}

/** Enciende el historial, guarda tres análisis y carga las reglas de ejemplo: la vista previa. */
async function rulesPreview(page) {
  await page.locator('#history-toggle').check();
  for (const [i, id] of ['03-phishing-banco', '04-phishing-correos', '02-legitimo-pedido'].entries()) {
    await page.getByRole('button', { name: title(id), exact: true }).click();
    await page.waitForFunction((t) => document.querySelector('#history-open').textContent === t, tx('app.history.open', { n: i + 1 }));
    await page.goto(`${server.url}/index.html`);
  }
  await page.locator('#rules > summary').click();
  await page.locator('#rules-file').setInputFiles(new URL('../samples/rules/ejemplo.json', import.meta.url).pathname);
  await page.locator('#rules-panel', { hasText: tx('rules.preview.summary.other', { count: 3 }).split('.')[0] }).waitFor();
  // La cabecera fija tapa lo primero: se deja a la vista el interruptor y el resumen «Reglas propias».
  await page.locator('.history-toggle').evaluate((n) => n.scrollIntoView({ block: 'start' }));
}

const server = await serve();
const browser = await chromium.launch();
const only = args;
for (const [name, sample, hash, width, colorScheme] of SHOTS.filter(([n]) => !only.length || only.includes(n))) {
  const page = await browser.newPage({ viewport: { width, height: width < 600 ? 844 : 900 }, deviceScaleFactor: 2, colorScheme, reducedMotion: 'reduce', locale: LOCALE });
  await page.goto(`${server.url}/index.html${hash}`);
  if (sample === 'historial') await savedHistory(page);
  else if (sample === 'panel') await savedPanel(page);
  else if (sample === 'reglas') await rulesPreview(page);
  else if (sample === 'forense' || sample === 'forense-dialogo') {
    await page.getByRole('button', { name: title('12-pdf-activo-zip'), exact: true }).click();
    await page.locator('#report .report__toolbar').waitFor();
    await page.getByRole('button', { name: tx('export.label') }).click();
    await page.getByRole('menuitem', { name: tx('export.forensic') }).click();
    await page.locator('[data-role="forensic-notes"]').fill(NOTES);
    if (sample === 'forense') {
      await page.getByRole('button', { name: tx('common.close') }).click();
      await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
      await page.emulateMedia({ media: 'print' });
    }
  }
  else if (sample) {
    await page.getByRole('button', { name: title(sample), exact: true }).click();
    await page.locator('#report > *').first().waitFor();
    await page.locator('#report').evaluate((n) => n.scrollIntoView({ block: 'start' }));
  }
  // El ratón se queda donde estaba el ejemplo: se aparta para que no salga ningún :hover.
  await page.mouse.move(0, 0);
  await page.waitForTimeout(300);
  // El panel es largo: se captura entero, pero solo el informe (sin la portada ni el pie).
  if (sample === 'panel') await page.locator('#report').screenshot({ path: `${OUT}${name}.png` });
  // El informe forense se captura como sale impreso: la primera hoja, más o menos.
  else if (sample === 'forense') {
    const box = await page.locator('#report .forensic').evaluate((e) => {
      const r = e.getBoundingClientRect();
      return { x: r.left + scrollX, y: r.top + scrollY, width: r.width, height: r.height };
    });
    await page.screenshot({ path: `${OUT}${name}.png`, fullPage: true, clip: { x: box.x, y: box.y, width: box.width, height: Math.min(box.height, 1270) } });
  }
  else await page.screenshot({ path: `${OUT}${name}.png` });
  await page.close();
  console.log(`${LANG === 'en' ? 'docs/img/en/' : 'docs/img/'}${name}.png`);
}
await browser.close();
await server.close();
