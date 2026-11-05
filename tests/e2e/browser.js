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
    return { browser: await playwright.chromium.launch() };
  } catch (e) {
    if (env.CI) throw e;
    return { skip: `Chromium no arranca (${String(e.message).split('\n')[0]}); instala con npx playwright install chromium` };
  }
}

/** Playwright y Chromium listos, o el motivo para saltar los tests. */
export async function openBrowser() {
  const loaded = loadPlaywright();
  return loaded.skip ? { skip: loaded.skip } : launchOrSkip(loaded.playwright);
}

/**
 * Abre una página que registra toda petición fuera de `origin` y toda violación de CSP.
 * Las peticiones externas se abortan: el test las ve, pero nunca salen de la máquina.
 */
export async function watchedPage(browser, origin, { colorScheme = 'light' } = {}) {
  const context = await browser.newContext({ colorScheme });
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
