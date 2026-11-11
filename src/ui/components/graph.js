import { el, svgEl } from '../dom.js';
import { t } from '../../i18n/index.js';

const MAX_LABEL = 24;
const PAD = 150; // margen lateral del lienzo para que los rótulos del anillo exterior no se corten
const LABELS_UP_TO = 40; // con más nodos solo se rotulan los correos: el resto va en aria-label y en la tabla
const TYPES = ['email', 'address', 'domain', 'ip', 'url', 'hash'];
const short = (text) => (text.length > MAX_LABEL ? `${text.slice(0, MAX_LABEL - 1)}…` : text);

/** Forma por tipo, además del color (WCAG 1.4.1). */
function shape(type, x, y) {
  const p = (pts) => svgEl('polygon', { className: 'graph__shape', attrs: { points: pts.map(([a, b]) => `${x + a},${y + b}`).join(' ') } });
  switch (type) {
    case 'email': return [svgEl('circle', { className: 'graph__shape', attrs: { cx: x, cy: y, r: 11 } })];
    case 'domain': return [svgEl('rect', { className: 'graph__shape', attrs: { x: x - 8, y: y - 8, width: 16, height: 16 } })];
    case 'ip': return [p([[0, -10], [10, 0], [0, 10], [-10, 0]])];
    case 'url': return [p([[0, -10], [9, 7], [-9, 7]])];
    case 'hash': return [p([[-9, -5], [0, -10], [9, -5], [9, 5], [0, 10], [-9, 5]])];
    default: return [
      svgEl('circle', { className: 'graph__shape', attrs: { cx: x, cy: y, r: 9 } }),
      svgEl('circle', { className: 'graph__shape graph__shape--inner', attrs: { cx: x, cy: y, r: 5 } }),
    ];
  }
}

/** Mini muestra de la forma de cada tipo para la leyenda. */
function legendIcon(type) {
  const icon = svgEl('svg', { attrs: { viewBox: '0 0 24 24', width: 18, height: 18, 'aria-hidden': 'true', focusable: 'false' }, className: `graph__icon graph__node--${type}` });
  icon.append(...shape(type, 12, 12));
  return icon;
}

/**
 * Grafo de IOCs ya preparado por el panel:
 * {nodes: [{id, type, typeLabel, text, x, y, relations}], edges: [{from, to}], total, hidden, size, current}.
 * Un solo paso de Tab (tabindex itinerante); las flechas recorren los nodos (graphKey en app.js).
 */
export function graphView(model) {
  const size = model.size ?? 640;
  const svg = svgEl('svg', {
    className: 'graph__svg',
    attrs: { viewBox: `${-PAD} -24 ${size + 2 * PAD} ${size + 48}`, role: 'group', 'aria-label': t('graph.label', { nodes: model.nodes.length, edges: model.edges.length }) },
  });
  const pos = new Map(model.nodes.map((n) => [n.id, n]));
  const lines = svgEl('g', { className: 'graph__edges', attrs: { 'aria-hidden': 'true' } });
  for (const e of model.edges) {
    const a = pos.get(e.from);
    const b = pos.get(e.to);
    if (!a || !b) continue;
    lines.append(svgEl('line', { className: 'graph__edge', attrs: { x1: a.x, y1: a.y, x2: b.x, y2: b.y, 'data-from': e.from, 'data-to': e.to } }));
  }
  svg.append(lines);
  const labelled = model.nodes.length <= LABELS_UP_TO;
  model.nodes.forEach((n, i) => {
    const name = `${n.typeLabel} ${n.text}, ${t('graph.relations', { count: n.relations })}`;
    const current = n.id === model.current;
    const g = svgEl('g', {
      className: `graph__node graph__node--${n.type}${current ? ' is-current' : ''}`,
      attrs: { role: 'img', 'aria-label': current ? t('graph.current', { name }) : name, tabindex: i === 0 ? '0' : '-1', 'data-node': n.id },
    });
    g.append(svgEl('title', { text: name }), ...shape(n.type, n.x, n.y));
    if (labelled || n.type === 'email') {
      // Rótulo hacia fuera del anillo: a la derecha de los nodos de la derecha y al revés.
      const c = size / 2;
      const side = n.type === 'email' || Math.abs(n.x - c) < 12 ? 'middle' : n.x > c ? 'start' : 'end';
      const x = side === 'middle' ? n.x : n.x + (side === 'start' ? 14 : -14);
      const y = side === 'middle' ? n.y + 26 : n.y + 4;
      g.append(svgEl('text', { className: 'graph__label', attrs: { x, y, 'text-anchor': side, 'aria-hidden': 'true' }, text: short(n.text) }));
    }
    svg.append(g);
  });
  const legend = el('ul', { className: 'graph__legend', attrs: { 'aria-label': 'Leyenda' } });
  for (const type of TYPES) {
    const label = model.typeLabels?.[type];
    if (label) legend.append(el('li', {}, legendIcon(type), label));
  }
  const figure = el('figure', { className: 'graph' },
    el('div', { className: 'graph__canvas' }, svg),
    el('figcaption', { className: 'graph__caption' },
      legend,
      el('p', { className: 'hint', text: 'Con el teclado: Tab entra en el grafo y las flechas pasan de un nodo a otro. Al enfocar un nodo se resaltan sus relaciones.' }),
      model.hidden > 0 ? el('p', { className: 'graph__note', text: `Se dibujan los ${model.nodes.length} nodos más conectados de ${model.total}.` }) : null));
  return figure;
}

/** Siguiente índice en el grafo según la tecla, o null si la tecla no es de navegación. */
export function graphKey(index, key, length) {
  const next = { ArrowRight: index + 1, ArrowDown: index + 1, ArrowLeft: index - 1, ArrowUp: index - 1, Home: 0, End: length - 1 }[key];
  if (next === undefined || !length) return null;
  return (next + length) % length;
}
