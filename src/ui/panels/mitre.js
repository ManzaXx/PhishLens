// Panel «ATT&CK»: técnicas que encajan con las señales.
import { el, externalLink } from '../dom.js';
import { t } from '../../i18n/index.js';


export function mitrePanel(report) {
  const panel = el('div');
  if (!report.techniques.length) {
    panel.append(el('p', { className: 'empty empty--muted', text: t('mitre.none') }));
    return panel;
  }
  panel.append(el('p', { className: 'hint', text: t('mitre.hint') }));
  const table = el('table', { className: 'mitre' });
  table.append(el('thead', {}, el('tr', {}, el('th', { text: t('mitre.technique') }), el('th', { text: t('mitre.name') }), el('th', { text: t('mitre.tactic') }), el('th', { text: t('mitre.signals') }))));
  const body = el('tbody');
  for (const t of report.techniques) {
    const count = report.findings.filter((f) => f.points && f.polarity !== 'trust' && f.techniques?.some((x) => x.id === t.id)).length;
    body.append(el('tr', {},
      el('td', {}, externalLink(t.url, t.id, 'mono')),
      el('td', { text: t.name, attrs: { title: t.why } }),
      el('td', { text: t.tactic }),
      el('td', { text: String(count) })));
  }
  table.append(body);
  panel.append(el('div', { className: 'table-wrap' }, table));
  return panel;
}
