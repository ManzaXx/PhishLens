// Pinta el informe en el modo elegido. Todo el contenido del email se inserta con textContent
// (src/ui/dom.js): nunca se interpreta como HTML ni se generan enlaces clicables a partir del email.
import { el } from './dom.js';
import { iocsToText } from '../intel/ioc.js';
import { toStixBundle } from '../intel/stix.js';
import { modeSwitch } from './components/mode-switch.js';
import { menuButton } from './components/menu-button.js';
import { batchBar } from './components/batch-bar.js';
import { renderSimple } from './views/simple.js';
import { renderAnalyst, renderPrint } from './views/analyst.js';

export const EXPORT_ITEMS = [
  { action: 'export-json', text: 'Descargar informe (JSON)' },
  { action: 'export-stix', text: 'Descargar STIX 2.1' },
  { action: 'copy-iocs', text: 'Copiar IOCs' },
  { action: 'print', text: 'Imprimir' },
];

/** Barra del informe: nivel de detalle, menú Exportar y la acción principal. */
function toolbar(mode) {
  return el('div', { className: 'report__toolbar' },
    modeSwitch(mode),
    el('div', { className: 'report__actions' },
      menuButton({ label: 'Exportar', items: EXPORT_ITEMS }),
      el('button', { className: 'btn btn--primary', text: 'Analizar otro', attrs: { type: 'button', 'data-action': 'new' } })));
}

/** Barra del lote a partir de su estado: {entries, skipped, campaigns, current}. */
function lotBar(batch) {
  const items = batch.entries
    .map(({ key, name, report }) => ({ key, name, level: report.level, label: report.label, score: report.score }))
    .sort((a, b) => String(a.name).localeCompare(String(b.name), 'es') || (a.key < b.key ? -1 : 1));
  return batchBar({ items, current: batch.current, campaigns: batch.campaigns?.length ?? 0, skipped: batch.skipped?.length ?? 0 });
}

/**
 * Dibuja el informe dentro de `container`.
 * options.mode: 'simple' | 'analyst'; options.view: vista del modo analista (ya resuelta);
 * options.authStatus, dkimKey y spfRecord: estado de la comprobación local de DKIM y SPF.
 * options.batch: el lote analizado (si lo hay), con su grafo y sus campañas.
 */
export function renderReport(container, report, options = {}) {
  const mode = options.mode === 'analyst' ? 'analyst' : 'simple';
  container.replaceChildren();
  container.className = `wrap report report--${mode} level-${report.level}`;
  const body = mode === 'analyst' ? renderAnalyst(report, options.view, options) : renderSimple(report, options);
  const saved = options.savedNote && !(mode === 'analyst' && (options.view === 'historial' || options.view === 'panel')) ? el('p', { className: 'saved-note', text: options.savedNote }) : null;
  container.append(...[toolbar(mode), saved, options.batch ? lotBar(options.batch) : null, body].filter(Boolean));
  container.hidden = false;
}

/** Añade (o quita, con report = null) el informe completo que sale al imprimir en cualquier modo. */
export function setPrintReport(container, report) {
  container.querySelector(':scope > .print-report')?.remove();
  if (report) container.append(renderPrint(report));
}

/** Versión de PhishLens: va en los informes y en cada entrada del historial. */
export const VERSION = '2.3.0';

/** Informe serializado para descargar. */
export function reportToJson(report) {
  return JSON.stringify({ tool: 'PhishLens', version: VERSION, generatedAt: new Date().toISOString(), ...report }, null, 2);
}

export { iocsToText };

/** STIX 2.1 de un correo o de un lote: el texto JSON (lo único que se serializa) y cuántos objetos lleva. */
export function stixJson(entries, { campaigns = [], now = new Date() } = {}) {
  const bundle = toStixBundle(entries, { campaigns, now });
  return { json: JSON.stringify(bundle, null, 2), count: bundle.objects.length };
}
