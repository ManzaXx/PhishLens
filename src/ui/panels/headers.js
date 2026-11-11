// Panel «Cabeceras y ruta».
import { el } from '../dom.js';
import { hopWarnings } from '../../detectors/route.js';
import { t } from '../../i18n/index.js';


/** Quién entregó el salto: HELO o From, con su DNS inverso si dice otra cosa. */
const hopName = (hop) => (hop.helo || hop.from || t('headers.unknown')) + (hop.rdns && hop.rdns !== hop.helo ? ` (${hop.rdns})` : '');

export function headersPanel(report) {
  const { email } = report;
  const panel = el('div', { className: 'stack' });
  const rows = [
    [t('headers.from'), email.from ? (email.from.name ? `${email.from.name} <${email.from.address}>` : email.from.address) : null],
    [t('headers.replyTo'), email.replyTo?.address],
    ['Return-Path', email.returnPath],
    [t('headers.subject'), email.subject],
    [t('headers.date'), email.date],
    [t('headers.auth'), email.authResults],
  ].filter(([, v]) => v);
  if (rows.length) {
    const dl = el('dl', { className: 'kv' });
    for (const [k, v] of rows) dl.append(el('dt', { text: k }), el('dd', { text: v }));
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: t('headers.key') }), dl));
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
          el('p', { className: 'route__hosts', text: `${hopName(hop)} → ${hop.by || t('headers.unknown')}` }),
          el('p', { className: 'route__meta', text: [hop.ip, hop.date].filter(Boolean).join(' · ') }),
          tags.childElementCount ? tags : null)));
    });
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: t('headers.route', { count: email.route.length }) }), ol));
  }
  if (!panel.childElementCount) panel.append(el('p', { className: 'empty empty--muted', text: t('headers.none') }));
  return panel;
}
