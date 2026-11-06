import { el } from '../dom.js';

const cell = (tag, value, attrs) => (value != null && typeof value === 'object'
  ? el(tag, { attrs }, value)
  : el(tag, { text: value ?? '', attrs }));

/**
 * Tabla con título y cabeceras de columna dentro de un contenedor desplazable con foco
 * (en móvil se desplaza en horizontal sin mover la página). Las celdas pueden ser texto o nodos.
 */
export function dataTable({ caption, columns, rows, className = '' }) {
  const table = el('table', { className: `data-table ${className}`.trim() },
    el('caption', { text: caption }),
    el('thead', {}, el('tr', {}, ...columns.map((c) => el('th', { text: c, attrs: { scope: 'col' } })))),
    el('tbody', {}, ...rows.map((r) => el('tr', {}, ...r.map((v) => cell('td', v))))));
  return el('div', { className: 'table-scroll', attrs: { tabindex: '0', role: 'region', 'aria-label': caption } }, table);
}
