// Pinta el informe en el modo elegido. Todo el contenido del email se inserta con textContent
// (src/ui/dom.js): nunca se interpreta como HTML ni se generan enlaces clicables a partir del email.
import { el } from './dom.js';
import { t, getLang, LOCALE } from '../i18n/index.js';
import { iocsToText } from '../intel/ioc.js';
import { toStixBundle } from '../intel/stix.js';
import { modeSwitch } from './components/mode-switch.js';
import { menuButton } from './components/menu-button.js';
import { batchBar } from './components/batch-bar.js';
import { renderSimple } from './views/simple.js';
import { renderAnalyst } from './views/analyst.js';
import { localizeReport } from './localize.js';

const EXPORTS = ['export-json', 'export-stix', 'copy-iocs', 'forensic'];
/** Opciones del menú Exportar, en el idioma activo. */
export const exportItems = () => EXPORTS.map((action) => ({ action, text: t(`export.${action}`) }));

/** Barra del informe: nivel de detalle, menú Exportar y la acción principal. */
function toolbar(mode) {
  return el('div', { className: 'report__toolbar' },
    modeSwitch(mode),
    el('div', { className: 'report__actions' },
      menuButton({ label: t('export.label'), items: exportItems() }),
      el('button', { className: 'btn btn--primary', text: t('report.new'), attrs: { type: 'button', 'data-action': 'new' } })));
}

/** Barra del lote a partir de su estado: {entries, skipped, campaigns, current}. */
function lotBar(batch) {
  const items = batch.entries
    .map(({ key, name, report }) => ({ key, name, level: report.level, label: t(`level.${report.level}`), score: report.score }))
    .sort((a, b) => String(a.name).localeCompare(String(b.name), LOCALE[getLang()]) || (a.key < b.key ? -1 : 1));
  return batchBar({ items, current: batch.current, campaigns: batch.campaigns?.length ?? 0, skipped: batch.skipped?.length ?? 0 });
}

/**
 * Dibuja el informe dentro de `container`.
 * options.mode: 'simple' | 'analyst'; options.view: vista del modo analista (ya resuelta);
 * options.authStatus, dkimKey y spfRecord: estado de la comprobación local de DKIM y SPF.
 * options.batch: el lote analizado (si lo hay), con su grafo y sus campañas.
 */
export function renderReport(container, original, options = {}) {
  const report = localizeReport(original);
  const mode = options.mode === 'analyst' ? 'analyst' : 'simple';
  container.replaceChildren();
  container.className = `wrap report report--${mode} level-${report.level}`;
  const body = mode === 'analyst' ? renderAnalyst(report, options.view, options) : renderSimple(report, options);
  const saved = options.savedNote && !(mode === 'analyst' && (options.view === 'historial' || options.view === 'panel')) ? el('p', { className: 'saved-note', text: options.savedNote }) : null;
  container.append(...[toolbar(mode), saved, options.batch ? lotBar(options.batch) : null, body].filter(Boolean));
  container.hidden = false;
}

/** Versión de PhishLens: va en los informes y en cada entrada del historial. */
export const VERSION = '3.1.0';

/** Informe serializado para descargar: `report` ya en el idioma `lang`, que también va en el JSON. */
export function reportToJson(report, lang = 'es') {
  return JSON.stringify({ tool: 'PhishLens', version: VERSION, lang: lang === 'en' ? 'en' : 'es', generatedAt: new Date().toISOString(), ...report }, null, 2);
}

export { iocsToText };

/** STIX 2.1 de un correo o de un lote: el texto JSON (lo único que se serializa) y cuántos objetos lleva. */
export function stixJson(entries, { campaigns = [], now = new Date(), lang = 'es', tr } = {}) {
  const bundle = toStixBundle(entries, { campaigns, now, lang, tr });
  return { json: JSON.stringify(bundle, null, 2), count: bundle.objects.length };
}
