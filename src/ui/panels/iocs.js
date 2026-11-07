// Panel «IOCs»: el grafo del lote (o del correo) con su tabla, y los indicadores del correo en formato defanged.
import { el } from '../dom.js';
import { defang, PLAIN, IOC_SECTIONS as IOC_LABELS } from '../../intel/ioc.js';
import { buildGraph, NODE_LABELS } from '../../intel/graph.js';
import { layoutGraph } from '../../intel/layout.js';
import { toUnicode } from '../../parser/punycode.js';
import { graphView } from '../components/graph.js';
import { dataTable } from '../components/data-table.js';

const TABLE_LIMIT = 500;

/** Texto de un nodo: defanged salvo hashes y correos (que no son clicables). */
const nodeText = (n) => (n.type === 'hash' || n.type === 'email' ? n.label : defang(n.value));

function degrees(graph) {
  const d = new Map();
  for (const e of graph.edges) {
    d.set(e.from, (d.get(e.from) ?? 0) + 1);
    d.set(e.to, (d.get(e.to) ?? 0) + 1);
  }
  return d;
}

/** Datos listos para graphView a partir del grafo y su disposición. */
export function graphModel(graph, layout, current = null) {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const d = degrees(graph);
  return {
    nodes: layout.nodes.map(({ id, x, y }) => {
      const n = byId.get(id);
      return { id, type: n.type, typeLabel: NODE_LABELS[n.type], text: nodeText(n), x, y, relations: d.get(id) ?? 0 };
    }),
    edges: layout.edges,
    total: graph.nodes.length,
    hidden: layout.hidden,
    typeLabels: NODE_LABELS,
    current,
  };
}

/** Tabla equivalente al grafo (lectores de pantalla y teclado), con un máximo de filas. */
export function graphTable(graph) {
  const d = degrees(graph);
  const rows = graph.nodes.slice(0, TABLE_LIMIT).map((n) => [NODE_LABELS[n.type], nodeText(n), String(n.emails.length), String(d.get(n.id) ?? 0)]);
  return el('div', { className: 'stack' },
    dataTable({ caption: 'Nodos del grafo', columns: ['Tipo', 'Valor', 'Correos', 'Relaciones'], rows, className: 'data-table--graph' }),
    graph.nodes.length > TABLE_LIMIT ? el('p', { className: 'graph__note', text: `Se muestran ${TABLE_LIMIT} de ${graph.nodes.length}.` }) : null);
}

function iocLists(report) {
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

export function iocsPanel(report, options = {}) {
  const batch = options.batch;
  const graph = batch?.graph ?? buildGraph([{ key: 'actual', name: report.email?.subject || 'Este correo', report }]);
  const current = batch ? `email:${batch.current}` : null;
  const section = (title, ...children) => el('section', { className: 'stack' }, el('h3', { text: title }), ...children);
  return el('div', { className: 'stack' },
    section(batch ? `Relaciones del lote (${batch.entries.length} correos)` : 'Relaciones de este correo',
      graph.nodes.length > 1 ? graphView(graphModel(graph, layoutGraph(graph), current)) : el('p', { className: 'empty empty--muted', text: 'No hay relaciones que dibujar.' }),
      graph.nodes.length > 1 ? graphTable(graph) : null),
    section('IOCs de este correo', iocLists(report)));
}
