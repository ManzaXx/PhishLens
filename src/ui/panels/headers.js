// Panel «Cabeceras y ruta».
import { el } from '../dom.js';
import { hopWarnings } from '../../detectors/route.js';


export function headersPanel(report) {
  const { email } = report;
  const panel = el('div', { className: 'stack' });
  const rows = [
    ['De', email.from ? (email.from.name ? `${email.from.name} <${email.from.address}>` : email.from.address) : null],
    ['Responder a', email.replyTo?.address],
    ['Return-Path', email.returnPath],
    ['Asunto', email.subject],
    ['Fecha', email.date],
    ['Autenticación', email.authResults],
  ].filter(([, v]) => v);
  if (rows.length) {
    const dl = el('dl', { className: 'kv' });
    for (const [k, v] of rows) dl.append(el('dt', { text: k }), el('dd', { text: v }));
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: 'Cabeceras clave' }), dl));
  }
  if (email.route?.length) {
    const ol = el('ol', { className: 'route' });
    const warnings = hopWarnings(email.route);
    email.route.forEach((hop, i) => {
      const tags = el('p', { className: 'route__tags' });
      for (const w of warnings[i]) {
        const kind = w.startsWith('Entrada') ? 'entry' : 'warn';
        tags.append(el('span', { className: `route__tag route__tag--${kind}`, text: w }));
      }
      ol.append(el('li', { className: warnings[i].length > (hop.entry ? 1 : 0) ? 'route__hop--warn' : '' },
        el('span', { className: 'route__step', text: String(i + 1) }),
        el('div', {},
          el('p', { className: 'route__hosts', text: `${hop.helo || hop.from || '¿?'}${hop.rdns && hop.rdns !== hop.helo ? ` (${hop.rdns})` : ''} → ${hop.by || '¿?'}` }),
          el('p', { className: 'route__meta', text: [hop.ip, hop.date].filter(Boolean).join(' · ') }),
          tags.childElementCount ? tags : null)));
    });
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: `Ruta del email (${email.route.length} saltos)` }), ol));
  }
  if (!panel.childElementCount) panel.append(el('p', { className: 'empty empty--muted', text: 'Sin cabeceras: pega el email original para ver esta parte.' }));
  return panel;
}
