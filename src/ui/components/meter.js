import { el, decimal } from '../dom.js';
import { severityKey } from './labels.js';

/** Fila de medidor: etiqueta, cifra «x / y» (leída «x de y») y una barra que solo acompaña. */
export function meter({ label, value, max, severity }) {
  const ratio = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0;
  const bar = el('span', { className: 'meter__bar' });
  bar.style.setProperty('--w', `${Math.round(ratio * 1000) / 10}%`);
  const tone = severity ? ` meter--${severityKey(severity)}` : '';
  return el('div', { className: `meter${tone}` },
    el('span', { className: 'meter__label', text: label }),
    el('span', { className: 'meter__value', text: `${decimal(value)} / ${max}`, attrs: { 'aria-label': `${decimal(value)} de ${max}` } }),
    el('span', { className: 'meter__track', attrs: { 'aria-hidden': 'true' } }, bar));
}
