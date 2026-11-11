// Carga Playwright si está instalado (npm ci en CI, o el del sistema). Si no, los tests e2e se saltan.
import { createRequire } from 'node:module';

export function loadPlaywright() {
  try {
    return { playwright: createRequire(import.meta.url)('playwright') };
  } catch (e) {
    return { skip: `playwright no está disponible (${e.code ?? e.message})` };
  }
}

/**
 * Arranca Chromium. Si no hay ejecutable, fuera de CI los tests se saltan con el motivo;
 * en CI (variable CI) es un fallo, para que un runner mal preparado no pase en verde sin probar nada.
 * @returns {Promise<{browser?: object, skip?: string}>}
 */
export async function launchOrSkip(playwright, env = process.env) {
  try {
    return { browser: withSpanishLocale(await playwright.chromium.launch()) };
  } catch (e) {
    if (env.CI) throw e;
    return { skip: `Chromium no arranca (${String(e.message).split('\n')[0]}); instala con npx playwright install chromium` };
  }
}

/**
 * Desde la 3.1 la app elige el idioma del navegador: los e2e abren en es-ES salvo que pidan otro
 * (locale en las opciones), así los textos esperados de siempre siguen valiendo.
 */
export function withSpanishLocale(browser) {
  if (typeof browser?.newContext !== 'function') return browser;
  const newContext = browser.newContext.bind(browser);
  browser.newContext = (options = {}) => newContext({ locale: 'es-ES', ...options });
  if (typeof browser.newPage === 'function') {
    const newPage = browser.newPage.bind(browser);
    browser.newPage = (options = {}) => newPage({ locale: 'es-ES', ...options });
  }
  return browser;
}

const warned = new Set();

/**
 * Un e2e saltado sale como «skipped» en el resumen y es fácil no verlo: se avisa en stderr, una vez por motivo
 * y proceso, para que nadie confunda «0 fallos» con «probado en el navegador».
 */
export function warnSkipped(reason, out = process.stderr) {
  if (!reason || warned.has(reason)) return false;
  warned.add(reason);
  out.write(`\n⚠️  E2E NO EJECUTADOS: ${reason}\n`
    + '   Los tests de navegador (privacidad, CSP, accesibilidad) se han SALTADO, no aprobado.\n'
    + '   En CI esto es un fallo; en local instala Chromium con: npx playwright install chromium\n\n');
  return true;
}

/** Playwright y Chromium listos, o el motivo para saltar los tests (avisando en stderr). */
export async function openBrowser() {
  const loaded = loadPlaywright();
  const r = loaded.skip ? { skip: loaded.skip } : await launchOrSkip(loaded.playwright);
  if (r.skip) warnSkipped(r.skip);
  return r;
}

/**
 * Abre una página que registra toda petición fuera de `origin` y toda violación de CSP.
 * Las peticiones externas se abortan: el test las ve, pero nunca salen de la máquina.
 */
export async function watchedPage(browser, origin, { colorScheme = 'light', locale } = {}) {
  const context = await browser.newContext(locale ? { colorScheme, locale } : { colorScheme });
  const external = [];
  await context.route('**/*', (route) => {
    const url = route.request().url();
    if (url.startsWith(`${origin}/`) || url.startsWith('data:') || url.startsWith('blob:')) return route.continue();
    external.push(url);
    return route.abort('blockedbyclient');
  });
  context.on('request', (r) => {
    const url = r.url();
    if (!url.startsWith(`${origin}/`) && !url.startsWith('data:') && !url.startsWith('blob:') && !external.includes(url)) external.push(url);
  });
  await context.addInitScript(() => {
    window.__cspViolations = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`));
  });
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  return { page, context, external, errors, violations: () => page.evaluate(() => window.__cspViolations) };
}
