// Panel «Resumen» del modo analista: anillo de riesgo, nivel, motivo y confianza.
import { el, svg } from '../dom.js';
import { confidenceLabel } from '../components/labels.js';
import { t } from '../../i18n/index.js';

function gauge(score) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const root = el('div', { className: 'gauge', attrs: { role: 'img', 'aria-label': t('summary.gauge', { score }) } });
  const ring = svg('svg', { viewBox: '0 0 120 120', 'aria-hidden': 'true' });
  ring.append(svg('circle', { class: 'gauge__track', cx: 60, cy: 60, r: radius, fill: 'none', 'stroke-width': 12 }));
  const value = svg('circle', {
    class: 'gauge__value', cx: 60, cy: 60, r: radius, fill: 'none', 'stroke-width': 12,
    'stroke-linecap': 'round', 'stroke-dasharray': circumference.toFixed(2),
  });
  value.style.strokeDashoffset = String(circumference);
  if (score === 0) value.style.opacity = '0';
  ring.append(value);
  const number = el('span', { className: 'gauge__score', text: '0' });
  root.append(ring, el('div', { className: 'gauge__label' }, number, el('span', { className: 'gauge__max', text: t('summary.of100') })));

  // Animación del anillo y del número (se respeta prefers-reduced-motion).
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    value.style.strokeDashoffset = String(circumference * (1 - score / 100));
  }));
  if (reduce) {
    number.textContent = String(score);
  } else {
    const start = performance.now();
    const tick = (t) => {
      const p = Math.min(1, (t - start) / 800);
      number.textContent = String(Math.round(score * (1 - (1 - p) ** 3)));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
  return root;
}

/** Pastilla de confianza con sus motivos desplegables. */
function confidenceBadge(confidence) {
  if (!confidence) return null;
  const box = el('div', { className: `confidence confidence--${confidence.level}` },
    el('span', { className: 'confidence__label', text: t('summary.confidence', { level: confidenceLabel(confidence.level) ?? '' }) }));
  if (confidence.reasons.length) {
    const list = el('ul', { className: 'confidence__reasons' });
    for (const reason of confidence.reasons) list.append(el('li', { text: reason }));
    box.append(el('details', {}, el('summary', { text: t('summary.why') }), list));
  }
  return box;
}

export function summaryPanel(report) {
  return el('div', { className: 'card report__head' },
    gauge(report.score),
    el('div', { className: 'report__verdict' },
      el('span', { className: 'verdict', text: report.label }),
      // Con nota 0 el motivo («no hay señales») repetiría el resumen.
      report.mainReason && report.score > 0 ? el('p', { className: 'report__reason' }, el('strong', { text: report.mainReason })) : null,
      el('p', { className: 'report__summary', text: report.summary }),
      confidenceBadge(report.confidence)));
}
