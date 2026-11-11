import { el } from '../dom.js';
import { t } from '../../i18n/index.js';

const DANGEROUS = new Set(['phishing', 'critical']);

/**
 * Selector del correo que se ve dentro de un lote: un <select> nativo (teclado y lector de pantalla
 * gratis) y un resumen en texto. items: [{key, name, level, label, score}].
 */
export function batchBar({ items, current, campaigns = 0, skipped = 0 }) {
  const select = el('select', { className: 'batch-bar__select', attrs: { id: 'batch-email' } });
  for (const item of items) {
    const attrs = { value: item.key };
    if (item.key === current) attrs.selected = '';
    select.append(el('option', { text: `${item.name} · ${item.label} · ${item.score}/100`, attrs }));
  }
  const parts = [
    t('batch.emails', { count: items.length }),
    t('batch.campaigns', { count: campaigns }),
    t('batch.dangerous', { count: items.filter((i) => DANGEROUS.has(i.level)).length }),
  ];
  if (skipped) parts.push(t('batch.skipped', { count: skipped }));
  return el('div', { className: 'batch-bar' },
    el('div', { className: 'batch-bar__field' },
      el('label', { className: 'batch-bar__label', text: t('batch.select'), attrs: { for: 'batch-email' } }),
      select),
    el('p', { className: 'batch-bar__summary', text: parts.join(' · ') }));
}
