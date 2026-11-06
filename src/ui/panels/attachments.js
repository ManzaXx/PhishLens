// Panel «Adjuntos»: tipo declarado frente a tipo real, hashes y lo que se ha leído por dentro.
// Todo lo que viene del adjunto (nombres, entradas del ZIP) se pinta como texto con el().
import { el, decimal } from '../dom.js';
import { dataTable } from '../components/data-table.js';
import { chip } from '../components/chip.js';
import { emptyState } from '../components/empty-state.js';

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
  if (!i) return chip('Sin leer');
  return chip(i.realLabel, { tone: mismatched ? 'phishing' : 'neutral' });
}

function hashRows(a) {
  const rows = [['SHA-256', a.sha256], ['SHA-1', a.sha1], ['MD5', a.md5]].filter(([, v]) => v);
  if (!rows.length) return [el('p', { className: 'muted', text: 'Sin hash: el adjunto está recortado, vacío o no se pudo leer entero.' })];
  return [el('dl', { className: 'hashes' }, ...rows.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { className: 'mono', text: v })]))];
}

function zipInside(zip) {
  if (!zip.ok) return [el('p', { text: `No se pudo leer: ${zip.reason}.` })];
  if (!zip.entries.length) return [el('p', { text: 'ZIP vacío.' })];
  const locked = zip.entries.filter((e) => e.encrypted).length;
  const n = zip.entries.length;
  const count = `${n}${zip.truncated ? ' o más' : ''} ${n === 1 ? 'entrada' : 'entradas'}`;
  const lockedText = locked ? `, ${locked} ${locked === 1 ? 'cifrada' : 'cifradas'} con contraseña` : '';
  const lines = [el('p', { text: `${count}${lockedText}${zip.vbaProject ? ', con macros VBA' : ''}.` })];
  const list = el('ul', { className: 'inside-list' }, ...zip.entries.slice(0, INNER_SHOWN).map((e) => el('li', { className: 'mono', text: e.name })));
  if (zip.entries.length > INNER_SHOWN) list.append(el('li', { text: `y ${zip.entries.length - INNER_SHOWN} más` }));
  lines.push(list);
  return lines;
}

function inside(a) {
  const i = a.inspection;
  if (!i) return 'No se ha mirado.';
  if (i.partial) return 'No se ha mirado dentro: el adjunto está recortado o no se pudo leer entero.';
  const parts = [];
  if (i.zip) parts.push(...zipInside(i.zip));
  if (i.ole) {
    parts.push(el('p', { text: i.ole.ok ? (i.ole.hasVba ? 'Lleva macros VBA.' : 'Sin macros.') : `No se pudo leer: ${i.ole.reason}.` }));
    if (i.ole.ok && i.ole.reason) parts.push(el('p', { className: 'muted', text: `Aviso: ${i.ole.reason}.` }));
  }
  if (i.pdf) {
    parts.push(el('p', { text: i.pdf.tokens.length ? `Instrucciones activas: ${i.pdf.tokens.map((t) => `/${t}`).join(', ')}.` : 'Sin instrucciones activas en el texto visible.' }));
    if (i.pdf.compressedStreams) parts.push(el('p', { className: 'muted', text: `${i.pdf.compressedStreams} flujos comprimidos sin mirar.` }));
  }
  if (i.html) parts.push(el('p', { text: i.html.suspicious ? `Crea archivos desde un script: ${i.html.markers.join(', ')}.` : 'Sin señales de que fabrique archivos.' }));
  if (!parts.length) return '—';
  return el('div', { className: 'inside' }, ...parts);
}

export function attachmentsPanel(report) {
  const list = report.email?.attachments ?? [];
  if (!list.length) return emptyState('Sin adjuntos', 'Este correo no trae ningún archivo adjunto.');
  const mismatched = new Set(report.findings.filter((f) => f.id === 'attachments.type-mismatch').map((f) => f.evidence));
  const rows = list.map((a) => [
    el('span', { className: 'mono attachment-name', text: a.filename }),
    el('span', {},
      el('span', { className: 'attachment-ext', text: a.inspection?.declaredExt ? `.${a.inspection.declaredExt}` : 'sin extensión' }),
      el('span', { className: 'muted attachment-mime', text: a.contentType })),
    realType(a, mismatched.has(a.filename)),
    formatSize(a.size),
    inside(a),
  ]);
  const hashes = el('section', { className: 'card hash-card' },
    el('h3', { className: 'group__title', text: 'Hashes para buscar en tu antivirus o en VirusTotal' }),
    ...list.map((a) => el('div', { className: 'hash-file' }, el('p', { className: 'mono attachment-name', text: a.filename }), ...hashRows(a))));
  return el('div', { className: 'stack' },
    el('p', { className: 'hint', text: 'PhishLens mira los adjuntos sin abrirlos: lee su tipo real por los primeros bytes y, si puede, la lista de lo que llevan dentro. No descomprime ni ejecuta nada.' }),
    dataTable({ caption: 'Adjuntos', columns: ['Nombre', 'Tipo declarado', 'Tipo real', 'Tamaño', 'Dentro'], rows, className: 'data-table--attachments' }),
    hashes);
}
