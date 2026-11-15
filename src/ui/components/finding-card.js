import { el, externalLink } from '../dom.js';
import { severityTag } from './severity-tag.js';
import { reliabilityLabel, severityKey } from './labels.js';
import { t } from '../../i18n/index.js';

/**
 * Tarjeta de una señal del modo analista: gravedad, fiabilidad, técnicas ATT&CK, detalle y evidencia.
 * Con `index` (posición en report.findings) la tarjeta lleva data-finding: es el destino de «Ver la prueba».
 */
export function findingCard(f, { index } = {}) {
  const risk = Boolean(f.points) && f.polarity !== 'trust';
  const techniques = risk ? f.techniques ?? [] : [];
  const meta = [reliabilityLabel(f.reliability), ...techniques.map((tech) => tech.id)].filter(Boolean).join(' · ');
  const links = el('div', { className: 'finding__meta' });
  for (const tech of techniques) {
    const link = externalLink(tech.url, `ATT&CK ${tech.id}`, 'mitre-tag');
    link.setAttribute('title', `${tech.name} (${tech.tactic}). ${tech.why}`);
    links.append(link);
  }
  const target = Number.isInteger(index) && index >= 0 ? { 'data-finding': String(index), tabindex: '-1' } : {};
  return el('article', { className: `finding sev-${severityKey(f.severity)}`, attrs: target },
    el('div', { className: 'finding__top' },
      severityTag(f.severity),
      el('h4', { className: 'finding__title', text: f.title }),
      f.custom ? el('span', { className: 'chip finding__custom', text: t('finding.custom') }) : null),
    f.points && meta ? el('p', { className: 'finding__line', text: meta }) : null,
    el('p', { className: 'finding__detail', text: f.detail }),
    f.evidence ? el('p', { className: 'finding__evidence', text: f.evidence }) : null,
    links.childElementCount ? links : null);
}
