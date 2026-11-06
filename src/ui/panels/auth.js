// Panel «Autenticación»: SPF, DKIM y DMARC, y la comprobación en local.
import { el } from '../dom.js';


const AUTH_ROWS = [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC']];

/** Texto de la insignia: el color nunca es la única señal del estado. */
export function authStateLabel(m) {
  switch (m.state) {
    case 'verified': return 'Verificado por PhishLens';
    case 'declared-trusted': return `Declarado por ${m.source || 'el receptor'}`;
    case 'declared-untrusted': return 'Declarado sin confirmar';
    case 'unverifiable': return 'No verificable sin DNS';
    default: return 'Sin datos';
  }
}

const RESULT_TONE = { pass: 'safe', fail: 'high', softfail: 'medium', permerror: 'medium', temperror: 'low', neutral: 'low', none: 'low' };

export function authPanel(report, { authStatus, dkimKey = '', spfRecord = '' } = {}) {
  const panel = el('div', { className: 'stack' });
  const auth = report.auth;
  if (!auth) return panel;

  const table = el('table', { className: 'auth-table' });
  table.append(el('thead', {}, el('tr', {},
    el('th', { text: 'Mecanismo', attrs: { scope: 'col' } }),
    el('th', { text: 'Resultado', attrs: { scope: 'col' } }),
    el('th', { text: 'Estado', attrs: { scope: 'col' } }))));
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
    el('h4', { className: 'group__title', text: 'SPF, DKIM y DMARC' }),
    el('p', { className: 'hint', text: '«Verificado» significa que PhishLens lo ha comprobado en tu navegador. «Declarado» es lo que dice una cabecera, que solo vale si la añadió el servidor que recibió el correo.' }),
    el('div', { className: 'table-wrap' }, table)));

  if (auth.headers.length) {
    const ul = el('ul', { className: 'auth-headers' });
    for (const h of auth.headers) {
      const kind = h.forged ? 'forged' : h.trusted ? 'trusted' : 'untrusted';
      const text = { forged: 'Falsificada', trusted: 'De confianza', untrusted: 'Sin confirmar' }[kind];
      ul.append(el('li', {},
        el('span', { className: `auth-state auth-state--${kind}`, text }),
        el('span', { className: 'mono', text: h.authservId || '(sin nombre)' }),
        el('span', { className: 'auth-detail', text: h.why })));
    }
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: `Cabeceras Authentication-Results (${auth.headers.length})` }), ul));
  }

  const isEmail = report.email.from !== null || report.email.authResults !== null;
  if (isEmail) {
    const details = el('details', { className: 'auth-local', attrs: authStatus ? { open: '' } : {} },
      el('summary', { text: 'Comprobar en local' }),
      el('p', { className: 'hint', text: 'Sin red: pega tú los registros DNS (por ejemplo, desde dig o un servicio de consulta DNS) y PhishLens los comprueba aquí mismo.' }),
      el('label', { text: 'Clave pública DKIM (registro TXT de selector._domainkey.dominio)', attrs: { for: 'dkim-key' } }),
      Object.assign(el('textarea', { attrs: { id: 'dkim-key', rows: '3', spellcheck: 'false', autocomplete: 'off', placeholder: 'v=DKIM1; k=rsa; p=MIIBIjANBg…' } }), { value: dkimKey }),
      el('button', { className: 'btn btn--small', text: 'Verificar firma', attrs: { type: 'button', 'data-action': 'verify-dkim' } }),
      el('label', { text: 'Registro SPF del dominio del sobre (Return-Path)', attrs: { for: 'spf-record' } }),
      Object.assign(el('textarea', { attrs: { id: 'spf-record', rows: '2', spellcheck: 'false', autocomplete: 'off', placeholder: 'v=spf1 ip4:192.0.2.0/24 -all' } }), { value: spfRecord }),
      el('button', { className: 'btn btn--small', text: 'Evaluar SPF', attrs: { type: 'button', 'data-action': 'eval-spf' } }),
      authStatus ? el('p', { className: 'auth-status', text: authStatus, attrs: { id: 'auth-status' } }) : null);
    panel.append(details);
  }
  return panel;
}
