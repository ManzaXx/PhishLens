import { el, externalLink } from '../dom.js';
import { severityTag } from './severity-tag.js';
import { RELIABILITY, severityKey } from './labels.js';

/** Tarjeta de una señal del modo analista: gravedad, fiabilidad, técnicas ATT&CK, detalle y evidencia. */
export function findingCard(f) {
  const risk = Boolean(f.points) && f.polarity !== 'trust';
  const techniques = risk ? f.techniques ?? [] : [];
  const meta = [RELIABILITY.get(f.reliability), ...techniques.map((t) => t.id)].filter(Boolean).join(' · ');
  const links = el('div', { className: 'finding__meta' });
  for (const t of techniques) {
    const link = externalLink(t.url, `ATT&CK ${t.id}`, 'mitre-tag');
    link.setAttribute('title', `${t.name} (${t.tactic}). ${t.why}`);
    links.append(link);
  }
  return el('article', { className: `finding sev-${severityKey(f.severity)}` },
    el('div', { className: 'finding__top' },
      severityTag(f.severity),
      el('h4', { className: 'finding__title', text: f.title })),
    f.points && meta ? el('p', { className: 'finding__line', text: meta }) : null,
    el('p', { className: 'finding__detail', text: f.detail }),
    f.evidence ? el('p', { className: 'finding__evidence', text: f.evidence }) : null,
    links.childElementCount ? links : null);
}
