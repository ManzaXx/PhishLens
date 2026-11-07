// Ayudantes de DOM de la UI. Todo el texto entra con textContent (nunca HTML) y pasa por reveal():
// un carácter RLO o invisible del email se muestra como ⟦U+202E⟧ en lugar de reordenar o esconder
// lo que se ve en el informe (ataque "Trojan Source").
import { reveal } from '../lib/text.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

/** Crea un elemento con clase, texto, atributos e hijos (nodos o cadenas; los nulos se ignoran). */
export function el(tag, { className, text, attrs } = {}, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = reveal(String(text));
  for (const [k, v] of Object.entries(attrs ?? {})) node.setAttribute(k, v);
  for (const child of children) {
    if (child == null || child === false) continue;
    node.append(typeof child === 'string' ? reveal(child) : child);
  }
  return node;
}

/** Crea un elemento SVG con atributos. */
export function svg(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

// Grafo de IOCs: solo estas etiquetas y atributos SVG. Nada de <a>, <script>, <foreignObject>,
// href ni manejadores on*: los valores del grafo vienen del correo.
const SVG_TAGS = new Set(['svg', 'g', 'line', 'circle', 'rect', 'polygon', 'path', 'text', 'title']);
const SVG_ATTRS = new Set([
  'viewBox', 'x', 'y', 'x1', 'y1', 'x2', 'y2', 'cx', 'cy', 'r', 'width', 'height', 'points', 'd', 'transform',
  'role', 'tabindex', 'aria-label', 'aria-labelledby', 'aria-hidden', 'focusable', 'data-node', 'data-from', 'data-to',
  'class', 'text-anchor', 'preserveAspectRatio',
]);

/** Elemento SVG con lista blanca de etiquetas y atributos; el texto va en textContent (revelado). */
export function svgEl(tag, { attrs, text, className } = {}) {
  if (!SVG_TAGS.has(tag)) throw new Error(`Etiqueta SVG no permitida: ${tag}`);
  const node = document.createElementNS(SVG_NS, tag);
  if (className) node.setAttribute('class', className);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (!SVG_ATTRS.has(k)) throw new Error(`Atributo SVG no permitido: ${k}`);
    node.setAttribute(k, String(v));
  }
  if (text != null) node.textContent = reveal(String(text));
  return node;
}

// Trazos de 24×24 (estilo línea). Map: una clave como "constructor" no sale del prototipo.
const ICONS = new Map([
  ['alert', ['M12 3l9 16H3L12 3z', 'M12 10v4', 'M12 17h.01']],
  ['check', ['M20 6L9 17l-5-5']],
  ['info', ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M12 11v5', 'M12 8h.01']],
  ['shield', ['M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6l8-3z']],
  ['menu', ['M4 6h16', 'M4 12h16', 'M4 18h16']],
  ['chevron', ['M9 6l6 6-6 6']],
]);

/** Icono decorativo (aria-hidden): el significado siempre va también en texto. */
export function icon(name) {
  const root = svg('svg', {
    class: `icon icon--${ICONS.has(name) ? name : 'info'}`, viewBox: '0 0 24 24', width: '20', height: '20',
    fill: 'none', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round',
    'aria-hidden': 'true', focusable: 'false',
  });
  for (const d of ICONS.get(name) ?? ICONS.get('info')) root.append(svg('path', { d }));
  return root;
}

const ALLOWED_LINK = /^https:\/\/attack\.mitre\.org\/techniques\/T\d{4}(\/\d{3})?\/$/;

/** Enlace externo propio de la app (documentación de MITRE), nunca uno del email. */
export function externalLink(href, text, className) {
  if (!ALLOWED_LINK.test(String(href))) return el('span', { className, text });
  return el('a', { className, text, attrs: { href, target: '_blank', rel: 'noopener noreferrer' } });
}

/** Número con coma decimal. */
export const decimal = (n) => String(n).replace('.', ',');

let uid = 0;
/** Id único por página para enlazar aria-labelledby. */
export const nextId = (prefix) => `${prefix}-${++uid}`;
