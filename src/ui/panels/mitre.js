// Panel «ATT&CK»: técnicas que encajan con las señales.
import { el, externalLink } from '../dom.js';


export function mitrePanel(report) {
  const panel = el('div');
  if (!report.techniques.length) {
    panel.append(el('p', { className: 'empty empty--muted', text: 'Ninguna técnica de ataque identificada.' }));
    return panel;
  }
  panel.append(el('p', { className: 'hint', text: 'Técnicas del marco MITRE ATT&CK que encajan con las señales encontradas.' }));
  const table = el('table', { className: 'mitre' });
  table.append(el('thead', {}, el('tr', {}, el('th', { text: 'Técnica' }), el('th', { text: 'Nombre' }), el('th', { text: 'Táctica' }), el('th', { text: 'Señales' }))));
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
