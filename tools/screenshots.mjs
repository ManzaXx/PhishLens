// Capturas de docs/img para el README. Se ejecuta a mano (no es un test): node tools/screenshots.mjs
// Usa el Chromium de Playwright y el servidor estático de los e2e; reduce el movimiento para que
// el anillo salga con su nota final.
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { serve } from '../tests/e2e/server.js';
import { SAMPLES } from '../samples/index.js';

const { chromium } = createRequire(import.meta.url)('playwright');
const OUT = fileURLToPath(new URL('../docs/img/', import.meta.url));
const title = (id) => SAMPLES.find((s) => s.id === id).title;

// [archivo, muestra o null (portada), hash, ancho, tema, ¿página entera?]
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
  ['analista-iocs', '10-dominio-unicode', '#analista/iocs', 1280, 'dark'],
  ['analista-attack', '03-phishing-banco', '#analista/attack', 1280, 'light'],
  ['movil-sencillo', '03-phishing-banco', '', 390, 'light'],
  ['movil-analista', '03-phishing-banco', '#analista/senales', 390, 'dark'],
];

const server = await serve();
const browser = await chromium.launch();
for (const [name, sample, hash, width, colorScheme] of SHOTS) {
  const page = await browser.newPage({ viewport: { width, height: width < 600 ? 844 : 900 }, deviceScaleFactor: 2, colorScheme, reducedMotion: 'reduce' });
  await page.goto(`${server.url}/index.html${hash}`);
  if (sample) {
    await page.getByRole('button', { name: title(sample), exact: true }).click();
    await page.locator('#report > *').first().waitFor();
    await page.locator('#report').evaluate((n) => n.scrollIntoView({ block: 'start' }));
  }
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${OUT}${name}.png` });
  await page.close();
  console.log(`docs/img/${name}.png`);
}
await browser.close();
await server.close();
