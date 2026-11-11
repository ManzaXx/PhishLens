// Panel «Autenticación»: SPF, DKIM y DMARC, y la comprobación en local.
import { el } from '../dom.js';
import { t } from '../../i18n/index.js';


const AUTH_ROWS = [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC']];

/** Texto de la insignia: el color nunca es la única señal del estado. */
export function authStateLabel(m) {
  switch (m.state) {
    case 'verified': return t('auth.state.verified');
    case 'declared-trusted': return t('auth.state.declared', { source: m.source || t('auth.state.receiver') });
    case 'declared-untrusted': return t('auth.state.untrusted');
    case 'unverifiable': return t('auth.state.unverifiable');
    default: return t('auth.state.none');
  }
}

const RESULT_TONE = { pass: 'safe', fail: 'high', softfail: 'medium', permerror: 'medium', temperror: 'low', neutral: 'low', none: 'low' };

export function authPanel(report, { authStatus, dkimKey = '', spfRecord = '' } = {}) {
  const panel = el('div', { className: 'stack' });
  const auth = report.auth;
  if (!auth) return panel;

  const table = el('table', { className: 'auth-table' });
  table.append(el('thead', {}, el('tr', {},
    el('th', { text: t('auth.col.mechanism'), attrs: { scope: 'col' } }),
    el('th', { text: t('auth.col.result'), attrs: { scope: 'col' } }),
    el('th', { text: t('auth.col.state'), attrs: { scope: 'col' } }))));
  const body = el('tbody');
  for (const [key, label] of AUTH_ROWS) {
    const m = auth[key];
    const tone = RESULT_TONE[m.result] ?? 'none';
    body.append(el('tr', { attrs: { 'data-auth': key } },
      el('th', { text: label, attrs: { scope: 'row' } }),
      el('td', {}, el('span', { className: `auth-result auth-result--${tone}`, text: m.result ?? '—' })),
      el('td', {},
        el('span', { className: `auth-state auth-state--${m.state}`, text: authStateLabel(m) }),
        m.detail ? el('p', { className: 'auth-detail', text: m.detail }) : null)));
  }
  table.append(body);
  panel.append(el('section', {},
    el('h4', { className: 'group__title', text: t('auth.title') }),
    el('p', { className: 'hint', text: t('auth.hint') }),
    el('div', { className: 'table-wrap' }, table)));

  if (auth.headers.length) {
    const ul = el('ul', { className: 'auth-headers' });
    for (const h of auth.headers) {
      const kind = h.forged ? 'forged' : h.trusted ? 'trusted' : 'untrusted';
      const text = t(`auth.header.${kind}`);
      ul.append(el('li', {},
        el('span', { className: `auth-state auth-state--${kind}`, text }),
        el('span', { className: 'mono', text: h.authservId || t('auth.header.noName') }),
        el('span', { className: 'auth-detail', text: h.why })));
    }
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: t('auth.headers', { n: auth.headers.length }) }), ul));
  }

  const isEmail = report.email.from !== null || report.email.authResults !== null;
  if (isEmail) {
    const details = el('details', { className: 'auth-local', attrs: authStatus ? { open: '' } : {} },
      el('summary', { text: t('auth.local') }),
      el('p', { className: 'hint', text: t('auth.local.hint') }),
      el('label', { text: t('auth.dkim.label'), attrs: { for: 'dkim-key' } }),
      Object.assign(el('textarea', { attrs: { id: 'dkim-key', rows: '3', spellcheck: 'false', autocomplete: 'off', placeholder: 'v=DKIM1; k=rsa; p=MIIBIjANBg…' } }), { value: dkimKey }), // i18n: ignore (registro DNS de ejemplo)
      el('button', { className: 'btn btn--small', text: t('auth.dkim.button'), attrs: { type: 'button', 'data-action': 'verify-dkim' } }),
      el('label', { text: t('auth.spf.label'), attrs: { for: 'spf-record' } }),
      Object.assign(el('textarea', { attrs: { id: 'spf-record', rows: '2', spellcheck: 'false', autocomplete: 'off', placeholder: 'v=spf1 ip4:192.0.2.0/24 -all' } }), { value: spfRecord }), // i18n: ignore (registro DNS de ejemplo)
      el('button', { className: 'btn btn--small', text: t('auth.spf.button'), attrs: { type: 'button', 'data-action': 'eval-spf' } }),
      authStatus ? el('p', { className: 'auth-status', text: authStatus, attrs: { id: 'auth-status' } }) : null);
    panel.append(details);
  }
  return panel;
}
