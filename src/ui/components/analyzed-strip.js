// Franja «Qué se ha analizado» (auditoría 3.1, P9): a qué correo corresponde el veredicto, en una tarjeta.
// Remitente (con el dominio resaltado), asunto, fecha que declara el correo, enlaces, adjuntos y autenticación
// en una línea. Todo lo que sale del correo entra con textContent y reveal() (src/ui/dom.js): ni HTML ni enlaces.
import { el, nextId } from '../dom.js';
import { t, fmtDate, fmtNumber } from '../../i18n/index.js';
import { authStateLabel } from './labels.js';

const MAX_TEXT = 200;
const MAX_NAMES = 3;
const RESULTS = new Set(['pass', 'fail', 'softfail', 'neutral', 'none', 'permerror', 'temperror', 'policy']);
const MECHANISMS = [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC']];

/** Texto recortado a `max` caracteres con «…»; el completo queda en `title` para quien lo necesite. */
function clipped(text, max = MAX_TEXT) {
  const s = String(text ?? '');
  return s.length > max ? { text: `${s.slice(0, max)}…`, title: s.slice(0, 2000) } : { text: s, title: null };
}

function dd(content, title) {
  const node = el('dd', { className: 'analyzed__value' }, ...(Array.isArray(content) ? content : [content]));
  if (title) node.setAttribute('title', title);
  return node;
}

const item = (name, label, value) => el('div', { className: `analyzed__item analyzed__item--${name}`, attrs: { 'data-row': name } },
  el('dt', { className: 'analyzed__label', text: label }), value);

/** «nombre» y «local@dominio», con el dominio en negrita: es la parte que decide quién envía. */
function sender(from) {
  if (!from?.address) return dd(t('analyzed.from.none'));
  const address = String(from.address);
  const at = address.lastIndexOf('@');
  const local = at >= 0 ? address.slice(0, at + 1) : address;
  const domain = at >= 0 ? address.slice(at + 1) : '';
  const name = from.name ? clipped(from.name, 120) : null;
  return dd([
    name ? el('span', { className: 'analyzed__name', text: name.text }) : null,
    el('span', { className: 'analyzed__address' }, el('span', { text: clipped(local, 120).text }), domain ? el('strong', { className: 'analyzed__domain', text: clipped(domain, 120).text }) : null),
  ].filter(Boolean));
}

/** La URL con su host en negrita. Si no se puede interpretar, va entera y sin resaltar. */
function urlValue(href) {
  const full = clipped(href, 300);
  let host = '';
  try { host = new URL(String(href)).hostname; } catch { /* se enseña tal cual */ }
  const i = host ? full.text.indexOf(host) : -1;
  if (i < 0) return dd(el('span', { className: 'analyzed__url', text: full.text }), full.title);
  return dd(el('span', { className: 'analyzed__url' },
    el('span', { text: full.text.slice(0, i) }),
    el('strong', { className: 'analyzed__domain', text: host }),
    el('span', { text: full.text.slice(i + host.length) })), full.title);
}

function dateValue(raw) {
  if (!raw) return dd(t('analyzed.date.none'));
  const nice = fmtDate(new Date(raw), { dateStyle: 'medium', timeStyle: 'short' });
  const shown = nice || clipped(raw, 80).text;
  return dd(shown, nice ? String(raw).slice(0, 200) : null);
}

function attachmentsValue(list) {
  const names = list.map((a) => clipped(a?.filename ?? a?.name ?? '', 80).text).filter(Boolean);
  if (!list.length) return dd('0');
  const shown = names.slice(0, MAX_NAMES).join(', ');
  const rest = list.length - Math.min(names.length, MAX_NAMES);
  const tail = rest > 0 ? t('analyzed.attachments.more', { list: shown, count: rest }) : shown;
  return dd(tail ? `${fmtNumber(list.length)} · ${tail}` : fmtNumber(list.length));
}

const FAILS = new Set(['fail', 'softfail', 'permerror']);
const TRUSTED = new Set(['verified', 'declared-trusted']);

/**
 * Modo sencillo, sin siglas: una frase con lo que dicen los resultados en los que se puede confiar (los que
 * verifica PhishLens o declara el receptor). Lo que solo declara el propio correo no cuenta como «supera».
 */
function plainAuth(auth, present) {
  const trusted = present.filter(([k]) => TRUSTED.has(auth[k].state)).map(([k]) => auth[k].result);
  if (!trusted.length) return t('analyzed.plain.untrusted');
  if (trusted.some((r) => FAILS.has(r))) return t('analyzed.plain.fail');
  if (trusted.length === MECHANISMS.length && trusted.every((r) => r === 'pass')) return t('analyzed.plain.pass');
  return t('analyzed.plain.partial');
}

/** «SPF falla · DKIM pasa · DMARC falla» y, debajo, quién lo dice (receptor, el propio correo, PhishLens). */
function authValue(auth, plain) {
  const present = MECHANISMS.filter(([k]) => auth?.[k] && auth[k].state !== 'absent');
  if (!present.length) return dd(t('analyzed.auth.none'));
  const line = plain ? plainAuth(auth, present) : MECHANISMS.map(([k, label]) => {
    const result = auth?.[k]?.state === 'absent' ? null : auth?.[k]?.result;
    return `${label} ${t(RESULTS.has(result) ? `analyzed.result.${result}` : 'analyzed.result.unknown')}`;
  }).join(' · ');
  const sources = [...new Set(present.map(([k]) => authStateLabel(auth[k])))].join(' · ');
  // En sencillo, «solo lo declara el propio correo» ya dice quién lo declara: no se repite debajo.
  const repeated = plain && line === t('analyzed.plain.untrusted');
  return dd([el('span', { className: 'analyzed__auth', text: line }), repeated ? null : el('span', { className: 'analyzed__source', text: sources })].filter(Boolean));
}

const hasHeaders = (email) => Boolean(email?.from || email?.date || email?.subject || email?.authResults?.length || email?.route?.length);

/**
 * Tarjeta «Qué se ha analizado». options.kind: 'eml' | 'text' | 'url' (cómo entró el correo). Una URL suelta
 * enseña solo la URL; un texto pegado sin cabeceras lo dice en lugar de llenar la tarjeta de «sin datos».
 * options.plain: modo sencillo, la autenticación en una frase sin siglas (SPF, DKIM, DMARC).
 */
export function analyzedStrip(report, { kind, plain = false } = {}) {
  const email = report?.email ?? {};
  const links = Array.isArray(email.links) ? email.links : [];
  const attachments = Array.isArray(email.attachments) ? email.attachments : [];
  const uniqueLinks = new Set(links.map((l) => String(l?.href ?? ''))).size;
  const id = nextId('analyzed');
  const rows = [];
  let note = null;
  if (kind === 'url') {
    rows.push(item('url', t('analyzed.url'), urlValue(links[0]?.href ?? '')));
    note = t('analyzed.note.url');
  } else if (kind === 'text' && !hasHeaders(email)) {
    rows.push(item('links', t('analyzed.links'), dd(fmtNumber(uniqueLinks))), item('attachments', t('analyzed.attachments'), attachmentsValue(attachments)));
    note = t('analyzed.note.text');
  } else {
    const subject = email.subject ? clipped(email.subject) : null;
    rows.push(
      item('from', t('analyzed.from'), sender(email.from)),
      item('subject', t('analyzed.subject'), subject ? dd(subject.text, subject.title) : dd(t('analyzed.subject.none'))),
      item('date', t('analyzed.date'), dateValue(email.date)),
      item('links', t('analyzed.links'), dd(fmtNumber(uniqueLinks))),
      item('attachments', t('analyzed.attachments'), attachmentsValue(attachments)),
      item('auth', t('analyzed.auth'), authValue(report?.auth, plain)));
  }
  return el('section', { className: 'analyzed', attrs: { 'aria-labelledby': id } },
    el('h2', { className: 'analyzed__title', text: t('analyzed.title'), attrs: { id } }),
    el('dl', { className: 'analyzed__list' }, ...rows),
    note ? el('p', { className: 'analyzed__note', text: note }) : null);
}
