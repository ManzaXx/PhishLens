// Gráficas de barras del panel (spec 3.0, §3; skill dataviz): SVG propio con svgEl (lista blanca),
// marcas finas con 2 px de separación, extremo de datos redondeado a 4 px, leyenda con texto y la
// tabla equivalente plegada debajo. Las etiquetas vienen del correo: van en textContent y recortadas.
import { el, svgEl, nextId } from '../dom.js';
import { dataTable } from './data-table.js';
import { t } from '../../i18n/index.js';

const MAX_LABEL = 80;
const GAP = 2;
const short = (s) => {
  const text = String(s);
  return text.length > MAX_LABEL ? `${text.slice(0, MAX_LABEL)}…` : text;
};
const sum = (counts, series) => series.reduce((n, s) => n + (Number(counts?.[s.key]) || 0), 0);

/** La tabla equivalente, plegada: los datos exactos están a un clic sin duplicar la gráfica en pantalla. */
const folded = (table) => el('details', { className: 'chart__data' }, el('summary', { text: t('chart.table') }), table);

function figure(caption, body, legend, table) {
  const id = nextId('chart');
  if (body.localName === 'svg' || body.tagName?.toLowerCase() === 'svg') body.setAttribute('aria-labelledby', id);
  return el('figure', { className: 'chart' },
    el('figcaption', { className: 'chart__caption', text: caption, attrs: { id } }),
    body, legend, folded(table));
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
    // Cada `labelEvery` cubos y siempre el último; el anterior se salta si quedaría pisándolo.
    const last = buckets.length - 1;
    if (i === last || (i % labelEvery === 0 && last - i >= labelEvery)) {
      root.append(svgEl('text', { attrs: { x: (x + barW / 2).toFixed(2), y: H - 8, 'text-anchor': 'middle', class: 'chart__tick' }, text: short(b.label) }));
    }
  });
  const legend = el('ul', { className: 'chart__legend' }, ...series.map((s) => el('li', {},
    el('span', { className: `chart__swatch chart__swatch--${s.key}`, attrs: { 'aria-hidden': 'true' } }), s.label)));
  const table = dataTable({
    caption,
    columns: [t('chart.date'), ...series.map((s) => s.label), t('chart.total')],
    rows: buckets.map((b, i) => [String(b.label), ...series.map((s) => String(Number(b.counts?.[s.key]) || 0)), String(totals[i])]),
    className: 'chart__table',
  });
  return figure(caption, root, legend, table);
}

/**
 * Barras horizontales: una fila por nombre. El nombre y el valor son texto HTML (se leen igual a 360 px
 * que a 1280 px) y la barra es un SVG decorativo de la fila. rows: [{label, value, detail?}].
 */
export function hBars({ caption, rows }) {
  const max = Math.max(1, ...rows.map((r) => Number(r.value) || 0));
  const list = el('ol', { className: 'chart__rows' }, ...rows.map((r) => {
    const v = Number(r.value) || 0;
    const track = svgEl('svg', { attrs: { viewBox: '0 0 100 8', preserveAspectRatio: 'none', class: 'chart__track', 'aria-hidden': 'true', focusable: 'false' } });
    const rect = svgEl('rect', { attrs: { x: 0, y: 0, width: ((v / max) * 100).toFixed(2), height: 8, class: 'chart__hbar' } });
    rect.append(svgEl('title', { text: `${short(r.label)}: ${v}` }));
    track.append(rect);
    return el('li', { className: 'chart__row' },
      el('span', { className: 'chart__label', text: short(r.label) }),
      track,
      el('span', { className: 'chart__value', text: String(v) }));
  }));
  const table = dataTable({
    caption,
    columns: [t('chart.name'), t('chart.detail'), t('chart.times')],
    rows: rows.map((r) => [String(r.label), String(r.detail ?? ''), String(Number(r.value) || 0)]),
    className: 'chart__table',
  });
  return figure(caption, list, null, table);
}
