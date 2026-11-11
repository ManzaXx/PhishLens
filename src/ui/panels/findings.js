// Panel «Señales»: todas las señales agrupadas por detector.
import { el } from '../dom.js';
import { findingCard } from '../components/finding-card.js';
import { t } from '../../i18n/index.js';


const DETECTORS = ['input', 'auth', 'sender', 'headers', 'route', 'links', 'lookalike', 'attachments', 'html', 'mime', 'language'];
/** Nombre del detector en el idioma activo; los desconocidos se quedan con su id. */
export const detectorLabel = (id) => (DETECTORS.includes(id) ? t(`detector.${id}`) : id);

export function findingsPanel(report) {
  const panel = el('div');
  if (report.findings.length === 0) {
    panel.append(el('p', { className: 'empty', text: t('findings.none') }));
    return panel;
  }
  const groups = new Map();
  for (const f of report.findings) {
    if (!groups.has(f.detector)) groups.set(f.detector, []);
    groups.get(f.detector).push(f);
  }
  for (const [detector, items] of groups) {
    const group = el('div', { className: 'group' }, el('h4', { className: 'group__title', text: detectorLabel(detector) }));
    for (const f of items) group.append(findingCard(f));
    panel.append(group);
  }
  for (const err of report.errors) {
    panel.append(el('p', { className: 'warning', text: t('findings.error', { detector: err.detector, message: err.message }) }));
  }
  return panel;
}
