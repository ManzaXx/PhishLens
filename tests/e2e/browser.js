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
