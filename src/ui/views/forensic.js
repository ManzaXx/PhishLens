// Informe forense para imprimir (spec 3.0, §4). Pinta el documento de intel/forensic.js tal cual, en el
// mismo orden; todo en textContent. La gravedad va en texto (severityTag), nunca solo en color.
import { el, nextId } from '../dom.js';
import { dataTable } from '../components/data-table.js';
import { severityTag } from '../components/severity-tag.js';
import { confidenceLabel } from '../components/labels.js';
import { t, fmtNumber } from '../../i18n/index.js';

const AUTH_STATES = new Set(['verified', 'declared-trusted', 'declared-untrusted', 'unverifiable', 'absent', 'none']);
const authState = (s) => (AUTH_STATES.has(s) ? t(`forensic.auth.${s}`) : s);
const none = (text) => el('p', { className: 'muted', text });

function section(title, ...children) {
  const id = nextId('forensic');
  return el('section', { className: 'forensic__section', attrs: { 'aria-labelledby': id } }, el('h2', { text: title, attrs: { id } }), ...children);
}

function identification(id) {
  const saved = id.savedAt != null;
  const missing = (v) => v ?? (saved ? t('forensic.notStored') : '—');
  const rows = [
    [t('forensic.id.file'), id.name ?? t('forensic.id.noFile')],
    [t('forensic.id.size'), id.size != null ? t('forensic.bytes', { n: fmtNumber(id.size) }) : missing(null)],
    ['SHA-256', id.sha256 ?? '—'],
    [t('forensic.id.hashOf'), id.hashOf === 'file' ? t('forensic.id.hashOf.file') : t('forensic.id.hashOf.text')],
    ['SHA-1', missing(id.sha1)],
    ['MD5', missing(id.md5)],
    [t('forensic.id.utc'), id.analyzedAt.utc],
    [t('forensic.id.local'), id.analyzedAt.local],
    saved ? [t('forensic.id.saved'), id.savedAt] : null,
    [t('forensic.id.version'), id.version],
  ].filter(Boolean);
  return el('dl', { className: 'forensic__facts' }, ...rows.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { className: /^(SHA|MD5)/.test(k) ? 'mono' : '', text: v })]));
}

const table = (caption, columns, rows) => dataTable({ caption, columns, rows, className: 'forensic__table' });

/** @param doc el resultado de forensicReport() */
export function renderForensic(doc) {
  const v = doc.verdict;
  const sections = [
    section(t('forensic.s.id'), identification(doc.identification)),
    section(t('forensic.s.verdict'),
      el('p', { className: 'forensic__verdict', text: t('forensic.verdict', { label: v.label ?? v.level, score: v.score ?? '—', confidence: confidenceLabel(v.confidence) ?? v.confidence ?? '—' }) }),
      v.headline ? el('p', { text: v.headline }) : null),
    section(t('forensic.s.findings'), doc.findings.length
      ? table(t('forensic.findings.caption'), [t('forensic.col.severity'), t('forensic.col.finding'), t('forensic.col.evidence'), t('forensic.col.technique')], doc.findings.map((f) => [
        severityTag(f.severity), el('span', {}, el('strong', { text: f.custom ? t('forensic.custom', { title: f.title ?? f.id }) : f.title ?? f.id }), f.detail ? el('span', { className: 'forensic__detail', text: f.detail }) : null),
        el('span', { className: 'mono', text: f.evidence || '—' }), f.technique ?? '—']))
      : none(t('forensic.findings.none'))),
    section(t('forensic.s.auth'), table(t('auth.title'), [t('auth.col.mechanism'), t('auth.col.state'), t('auth.col.result'), t('forensic.col.detail')],
      ['spf', 'dkim', 'dmarc'].map((k) => [k.toUpperCase(), authState(doc.auth[k].state), doc.auth[k].result ?? '—', doc.auth[k].detail ?? '—']))),
    section(t('forensic.s.timeline'),
      el('p', { text: t('forensic.timeline.date', { date: doc.timeline.date ?? t('forensic.timeline.noDate') }) }),
      doc.timeline.hops.length
        ? table(t('forensic.hops.caption'), ['#', t('forensic.col.from'), t('forensic.col.by'), 'IP', t('forensic.col.date'), 'UTC', t('forensic.col.backwards')], doc.timeline.hops.map((h, i) => [
          String(i + 1), h.from ?? '—', h.by ?? '—', h.ip ?? '—', h.date ?? '—', h.utc ?? '—', h.backwards ? t('forensic.backwards.yes') : t('forensic.backwards.no')]))
        : none(t('forensic.hops.none'))),
    section('IOCs', ...(doc.iocs.length
      ? doc.iocs.map((g) => el('div', { className: 'forensic__iocs' }, el('h3', { text: `${g.label} (${g.items.length})` }),
        el('ul', {}, ...g.items.map((i) => el('li', { className: 'mono', text: i })))))
      : [none(t('forensic.iocs.none'))])),
    section(t('attachments.caption'), doc.attachments.length
      ? table(t('attachments.caption'), [t('attachments.col.name'), t('attachments.col.declared'), t('attachments.col.real'), t('attachments.col.size'), t('forensic.col.hashes'), t('forensic.col.seen')], doc.attachments.map((a) => [
        el('span', { className: 'mono', text: a.name ?? '—' }), a.declaredType ?? '—', a.realType ?? '—', a.size != null ? t('forensic.bytes', { n: fmtNumber(a.size) }) : '—',
        el('span', { className: 'mono forensic__hashes', text: [['SHA-256', a.sha256], ['SHA-1', a.sha1], ['MD5', a.md5]].filter(([, x]) => x).map(([k, x]) => `${k} ${x}`).join('\n') || t('forensic.noHash') }),
        a.seen]))
      : none(t('forensic.attachments.none'))),
    section('URLs', ...(doc.urls.items.length
      ? [table(t('forensic.urls.caption'), ['URL', t('urls.final'), t('forensic.col.hops'), t('forensic.col.chain')], doc.urls.items.map((u) => [
        el('span', { className: 'mono', text: u.url }), el('span', { className: 'mono', text: u.final ?? '—' }), String(u.hops), el('span', { className: 'mono', text: u.chain })])),
      doc.urls.total > doc.urls.items.length ? none(t('forensic.urls.limit', { shown: doc.urls.items.length, total: doc.urls.total })) : null]
      : [none(t('forensic.urls.none'))])),
    doc.notes != null ? section(t('forensic.s.notes'), el('p', { className: 'forensic__notes', text: doc.notes })) : null,
    section(t('forensic.s.limits'), el('p', { text: doc.limits })),
  ];
  return el('div', { className: 'forensic' },
    el('header', { className: 'forensic__head' },
      el('h1', { text: t('forensic.doc.title') }),
      el('p', { className: 'forensic__hint', text: t('forensic.doc.hint') })),
    ...sections,
    el('p', { className: 'forensic__footer mono', text: t('forensic.footer', { sha: doc.identification.sha256 ?? t('forensic.unavailable') }) }));
}
