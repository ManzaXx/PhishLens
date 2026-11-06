// Panel «IOCs»: indicadores en formato defanged.
import { el } from '../dom.js';
import { defang, PLAIN, IOC_SECTIONS as IOC_LABELS } from '../../intel/ioc.js';
import { toUnicode } from '../../parser/punycode.js';


export function iocsPanel(report) {
  const panel = el('div', { className: 'stack' });
  const total = IOC_LABELS.reduce((n, [k]) => n + (report.iocs[k]?.length ?? 0), 0);
  if (!total) {
    panel.append(el('p', { className: 'empty empty--muted', text: 'No hay indicadores que extraer.' }));
    return panel;
  }
  panel.append(el('div', { className: 'ioc-head' },
    el('p', { className: 'hint', text: 'Indicadores de compromiso en formato "defanged" (hxxp, [.]) para compartirlos sin riesgo de clic.' }),
    el('button', { className: 'btn btn--small', text: 'Copiar IOCs', attrs: { type: 'button', 'data-action': 'copy-iocs' } })));
  const grid = el('div', { className: 'ioc-grid' });
  for (const [key, label] of IOC_LABELS) {
    const values = report.iocs[key] ?? [];
    if (!values.length) continue;
    const ul = el('ul', { className: 'ioc-list' });
    for (const v of values.slice(0, 50)) {
      const shown = PLAIN.has(key) ? v : defang(v);
      // Dominios internacionales: también en Unicode, para ver qué letras hay de verdad.
      const unicode = key === 'domains' && /(^|\.)xn--/i.test(v) ? toUnicode(v) : null;
      ul.append(el('li', { text: unicode && unicode !== v ? `${shown} (${defang(unicode)})` : shown }));
    }
    grid.append(el('section', {}, el('h4', { className: 'group__title', text: `${label} (${values.length})` }), ul));
  }
  panel.append(grid);
  return panel;
}
