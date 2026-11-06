// Pinta el informe en el modo elegido. Todo el contenido del email se inserta con textContent
// (src/ui/dom.js): nunca se interpreta como HTML ni se generan enlaces clicables a partir del email.
import { el } from './dom.js';
import { iocsToText } from '../intel/ioc.js';
import { modeSwitch } from './components/mode-switch.js';
import { menuButton } from './components/menu-button.js';
import { renderSimple } from './views/simple.js';
import { renderAnalyst } from './views/analyst.js';

const EXPORT_ITEMS = [
  { action: 'export-json', text: 'Descargar informe (JSON)' },
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

/**
 * Dibuja el informe dentro de `container`.
 * options.mode: 'simple' | 'analyst'; options.view: vista del modo analista (ya resuelta);
 * options.authStatus, dkimKey y spfRecord: estado de la comprobación local de DKIM y SPF.
 */
export function renderReport(container, report, options = {}) {
  const mode = options.mode === 'analyst' ? 'analyst' : 'simple';
  container.replaceChildren();
  container.className = `wrap report report--${mode} level-${report.level}`;
  const body = mode === 'analyst' ? renderAnalyst(report, options.view, options) : renderSimple(report);
  container.append(toolbar(mode), body);
  container.hidden = false;
}

/** Informe serializado para descargar. */
export function reportToJson(report) {
  return JSON.stringify({ tool: 'PhishLens', version: '2.2.0', generatedAt: new Date().toISOString(), ...report }, null, 2);
}

export { iocsToText };
