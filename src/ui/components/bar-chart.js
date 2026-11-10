// Gráficas de barras del panel (spec 3.0, §3; skill dataviz): SVG propio con svgEl (lista blanca),
// marcas finas con 2 px de separación, extremo de datos redondeado a 4 px, leyenda con texto y la
// tabla equivalente siempre al lado. Las etiquetas vienen del correo: van en textContent y recortadas.
import { el, svgEl, nextId } from '../dom.js';
import { dataTable } from './data-table.js';

const MAX_LABEL = 80;
const GAP = 2;
const short = (s) => {
  const t = String(s);
  return t.length > MAX_LABEL ? `${t.slice(0, MAX_LABEL)}…` : t;
};
const sum = (counts, series) => series.reduce((n, s) => n + (Number(counts?.[s.key]) || 0), 0);

function figure(caption, svgNode, legend, table) {
  const id = nextId('chart');
  svgNode.setAttribute('aria-labelledby', id);
  return el('figure', { className: 'chart' },
    el('figcaption', { className: 'chart__caption', text: caption, attrs: { id } }),
    svgNode, legend, table);
}

/** Barras apiladas por cubo (p. ej. días) y serie (p. ej. nivel). buckets: [{label, counts: {clave: n}}]. */
export function stackedBars({ caption, buckets, series }) {
  const W = 640;
  const H = 240;
  const pad = { top: 8, right: 8, bottom: 28, left: 32 };
  const plotH = H - pad.top - pad.bottom;
  const plotW = W - pad.left - pad.right;
  const totals = buckets.map((b) => sum(b.counts, series));
  const max = Math.max(1, ...totals);
  const slot = plotW / Math.max(1, buckets.length);
  const barW = Math.max(2, Math.min(28, slot * 0.7));
  const root = svgEl('svg', { attrs: { viewBox: `0 0 ${W} ${H}`, role: 'img', class: 'chart__svg', preserveAspectRatio: 'xMidYMid meet' } });
  const base = pad.top + plotH;
  root.append(svgEl('line', { attrs: { x1: pad.left, x2: W - pad.right, y1: base, y2: base, class: 'chart__axis' } }));
  root.append(svgEl('text', { attrs: { x: pad.left - 6, y: pad.top + 10, 'text-anchor': 'end', class: 'chart__tick' }, text: String(max) }));
  root.append(svgEl('text', { attrs: { x: pad.left - 6, y: base, 'text-anchor': 'end', class: 'chart__tick' }, text: '0' }));
  const labelEvery = Math.ceil(buckets.length / 8);
  buckets.forEach((b, i) => {
    const x = pad.left + i * slot + (slot - barW) / 2;
    const parts = series.map((s) => ({ s, n: Number(b.counts?.[s.key]) || 0 })).filter((p) => p.n > 0);
    let y = base;
    parts.forEach((p, k) => {
      const h = Math.max(1, (p.n / max) * plotH - (k ? GAP : 0));
      y -= h + (k ? GAP : 0);
      const attrs = { x: x.toFixed(2), y: y.toFixed(2), width: barW.toFixed(2), height: h.toFixed(2), class: `chart__bar chart__bar--${p.s.key}` };
      if (k === parts.length - 1) attrs.rx = 4;
      const rect = svgEl('rect', { attrs });
      rect.append(svgEl('title', { text: `${short(b.label)}: ${p.n} ${p.s.label}` }));
      root.append(rect);
    });
    if (i % labelEvery === 0 || i === buckets.length - 1) {
      root.append(svgEl('text', { attrs: { x: (x + barW / 2).toFixed(2), y: H - 8, 'text-anchor': 'middle', class: 'chart__tick' }, text: short(b.label) }));
    }
  });
  const legend = el('ul', { className: 'chart__legend' }, ...series.map((s) => el('li', {},
    el('span', { className: `chart__swatch chart__swatch--${s.key}`, attrs: { 'aria-hidden': 'true' } }), s.label)));
  const table = dataTable({
    caption,
    columns: ['Fecha', ...series.map((s) => s.label), 'Total'],
    rows: buckets.map((b, i) => [String(b.label), ...series.map((s) => String(Number(b.counts?.[s.key]) || 0)), String(totals[i])]),
    className: 'chart__table',
  });
  return figure(caption, root, legend, table);
}

/** Barras horizontales: una fila por nombre, con su valor en texto. rows: [{label, value, detail?}]. */
export function hBars({ caption, rows }) {
  const W = 640;
  const ROW = 28;
  const labelW = 240;
  const valueW = 40;
  const H = Math.max(ROW, rows.length * ROW);
  const max = Math.max(1, ...rows.map((r) => Number(r.value) || 0));
  const plotW = W - labelW - valueW;
  const root = svgEl('svg', { attrs: { viewBox: `0 0 ${W} ${H}`, role: 'img', class: 'chart__svg', preserveAspectRatio: 'xMidYMid meet' } });
  rows.forEach((r, i) => {
    const y = i * ROW;
    const v = Number(r.value) || 0;
    const w = (v / max) * plotW;
    root.append(svgEl('text', { attrs: { x: labelW - 8, y: y + ROW / 2 + 4, 'text-anchor': 'end', class: 'chart__label' }, text: short(r.label) }));
    const rect = svgEl('rect', { attrs: { x: labelW, y: y + 6, width: w.toFixed(2), height: ROW - 12, rx: 4, class: 'chart__hbar' } });
    rect.append(svgEl('title', { text: `${short(r.label)}: ${v}` }));
    root.append(rect);
    root.append(svgEl('text', { attrs: { x: (labelW + w + 6).toFixed(2), y: y + ROW / 2 + 4, class: 'chart__value' }, text: String(v) }));
  });
  const table = dataTable({
    caption,
    columns: ['Nombre', 'Detalle', 'Veces'],
    rows: rows.map((r) => [String(r.label), String(r.detail ?? ''), String(Number(r.value) || 0)]),
    className: 'chart__table',
  });
  return figure(caption, root, null, table);
}
