// Panel «Adjuntos»: tipo declarado frente a tipo real, hashes y lo que se ha leído por dentro.
// Todo lo que viene del adjunto (nombres, entradas del ZIP) se pinta como texto con el().
import { el, decimal } from '../dom.js';
import { dataTable } from '../components/data-table.js';
import { chip } from '../components/chip.js';
import { emptyState } from '../components/empty-state.js';
import { t } from '../../i18n/index.js';

const INNER_SHOWN = 10;

export function formatSize(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${decimal(Math.round(kb * 10) / 10)} KB`;
  return `${decimal(Math.round((kb / 1024) * 10) / 10)} MB`;
}

function realType(a, mismatched) {
  const i = a.inspection;
  if (!i) return chip(t('attachments.unread'));
  if (!mismatched) return chip(i.realLabel);
  // El color no es la única señal: se dice también en texto (WCAG 1.4.1).
  return el('span', { className: 'real-type' },
    chip(i.realLabel, { tone: 'phishing' }),
    el('span', { className: 'real-type__note', text: i.declaredExt ? t('attachments.mismatch.ext', { ext: i.declaredExt }) : t('attachments.mismatch.name') }));
}

function hashRows(a) {
  const rows = [['SHA-256', a.sha256], ['SHA-1', a.sha1], ['MD5', a.md5]].filter(([, v]) => v);
  if (!rows.length) return [el('p', { className: 'muted', text: t('attachments.nohash') })];
  return [el('dl', { className: 'hashes' }, ...rows.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { className: 'mono', text: v })]))];
}

function zipInside(zip) {
  if (!zip.ok) return [el('p', { text: t('attachments.unreadable', { reason: zip.reason }) })];
  const partial = zip.complete === false
    ? el('p', { className: 'muted', text: t('attachments.zip.partial') })
    : null;
  if (!zip.entries.length) return [partial ?? el('p', { text: t('attachments.zip.empty') })];
  const locked = zip.entries.filter((e) => e.encrypted).length;
  const n = zip.entries.length;
  const parts = [
    zip.truncated ? t('attachments.zip.entriesMore', { n }) : t('attachments.zip.entries', { count: n }),
    locked ? t('attachments.zip.locked', { count: locked }) : null,
    zip.vbaProject ? t('attachments.zip.vba') : null,
  ].filter(Boolean);
  const lines = [el('p', { text: `${parts.join(', ')}.` })];
  const list = el('ul', { className: 'inside-list' }, ...zip.entries.slice(0, INNER_SHOWN).map((e) => el('li', { className: 'mono', text: e.name })));
  if (zip.entries.length > INNER_SHOWN) list.append(el('li', { text: t('attachments.zip.more', { n: zip.entries.length - INNER_SHOWN }) }));
  lines.push(list);
  if (partial) lines.push(partial);
  return lines;
}

function inside(a) {
  const i = a.inspection;
  if (!i) return t('attachments.notLooked');
  if (i.partial) return t('attachments.partial');
  const parts = [];
  if (i.zip) parts.push(...zipInside(i.zip));
  if (i.ole) {
    let text;
    if (!i.ole.ok) text = t('attachments.unreadable', { reason: i.ole.reason });
    else if (i.ole.hasVba) text = t('attachments.ole.vba');
    else if (i.ole.complete === false) text = t('attachments.ole.partial');
    else text = t('attachments.ole.clean');
    parts.push(el('p', { text }));
  }
  if (i.pdf) {
    parts.push(el('p', { text: i.pdf.tokens.length ? t('attachments.pdf.tokens', { list: i.pdf.tokens.map((tok) => `/${tok}`).join(', ') }) : t('attachments.pdf.clean') }));
    if (i.pdf.compressedStreams) parts.push(el('p', { className: 'muted', text: t('attachments.pdf.streams', { count: i.pdf.compressedStreams }) }));
  }
  if (i.html) parts.push(el('p', { text: i.html.suspicious ? t('attachments.html.smuggling', { list: i.html.markers.join(', ') }) : t('attachments.html.clean') }));
  if (!parts.length) return '—';
  return el('div', { className: 'inside' }, ...parts);
}

export function attachmentsPanel(report) {
  const list = report.email?.attachments ?? [];
  if (!list.length) return emptyState(t('attachments.empty.title'), t('attachments.empty.text'));
  const mismatched = new Set(report.findings.filter((f) => f.id === 'attachments.type-mismatch').map((f) => f.evidence));
  const rows = list.map((a) => [
    el('span', { className: 'mono attachment-name', text: a.filename }),
    el('span', {},
      el('span', { className: 'attachment-ext', text: a.inspection?.declaredExt ? `.${a.inspection.declaredExt}` : t('attachments.noExt') }),
      el('span', { className: 'muted attachment-mime', text: a.contentType })),
    realType(a, mismatched.has(a.filename)),
    formatSize(a.size),
    inside(a),
  ]);
  const hashes = el('section', { className: 'card hash-card' },
    el('h3', { className: 'group__title', text: t('attachments.hashes') }),
    ...list.map((a) => el('div', { className: 'hash-file' }, el('p', { className: 'mono attachment-name', text: a.filename }), ...hashRows(a))));
  return el('div', { className: 'stack' },
    el('p', { className: 'hint', text: t('attachments.hint') }),
    dataTable({ caption: t('attachments.caption'), columns: [t('attachments.col.name'), t('attachments.col.declared'), t('attachments.col.real'), t('attachments.col.size'), t('attachments.col.inside')], rows, className: 'data-table--attachments' }),
    hashes);
}
