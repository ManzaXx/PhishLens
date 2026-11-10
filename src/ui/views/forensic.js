// Informe forense para imprimir (spec 3.0, §4). Pinta el documento de intel/forensic.js tal cual, en el
// mismo orden; todo en textContent. La gravedad va en texto (severityTag), nunca solo en color.
import { el, nextId } from '../dom.js';
import { dataTable } from '../components/data-table.js';
import { severityTag } from '../components/severity-tag.js';
import { CONFIDENCE } from '../components/labels.js';

const NOT_STORED = 'No disponible: el correo no se guarda';
const AUTH_STATE = new Map([['verified', 'Verificado'], ['declared-trusted', 'Declarado por el receptor'], ['declared-untrusted', 'Declarado sin confirmar'], ['unverifiable', 'No verificable'], ['absent', 'Sin datos'], ['none', 'Sin datos']]);
const none = (text) => el('p', { className: 'muted', text });

function section(title, ...children) {
  const id = nextId('forensic');
  return el('section', { className: 'forensic__section', attrs: { 'aria-labelledby': id } }, el('h2', { text: title, attrs: { id } }), ...children);
}

function identification(id) {
  const saved = id.savedAt != null;
  const missing = (v) => v ?? (saved ? NOT_STORED : '—');
  const rows = [
    ['Fichero', id.name ?? 'Sin fichero (texto pegado o URL)'],
    ['Tamaño', id.size != null ? `${String(id.size).replace(/\B(?=(\d{3})+(?!\d))/g, '.')} bytes` : missing(null)],
    ['SHA-256', id.sha256 ?? '—'],
    ['Hashes de', id.hashOf === 'file' ? 'Los bytes del fichero tal cual (coinciden con sha256sum)' : 'El texto analizado en UTF-8 (puede no coincidir con sha256sum del fichero original)'],
    ['SHA-1', missing(id.sha1)],
    ['MD5', missing(id.md5)],
    ['Analizado (UTC)', id.analyzedAt.utc],
    ['Analizado (hora local)', id.analyzedAt.local],
    saved ? ['Guardado en el historial', id.savedAt] : null,
    ['Versión de PhishLens', id.version],
  ].filter(Boolean);
  return el('dl', { className: 'forensic__facts' }, ...rows.flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { className: /^(SHA|MD5)/.test(k) ? 'mono' : '', text: v })]));
}

const table = (caption, columns, rows) => dataTable({ caption, columns, rows, className: 'forensic__table' });

/** @param doc el resultado de forensicReport() */
export function renderForensic(doc) {
  const v = doc.verdict;
  const sections = [
    section('Identificación', identification(doc.identification)),
    section('Veredicto',
      el('p', { className: 'forensic__verdict', text: `${v.label ?? v.level} · ${v.score ?? '—'}/100 · confianza ${CONFIDENCE.get(v.confidence) ?? v.confidence ?? '—'}` }),
      v.headline ? el('p', { text: v.headline }) : null),
    section('Hallazgos', doc.findings.length
      ? table('Hallazgos por gravedad', ['Gravedad', 'Hallazgo', 'Evidencia', 'Técnica'], doc.findings.map((f) => [
        severityTag(f.severity), el('span', {}, el('strong', { text: f.custom ? `${f.title ?? f.id} (regla propia)` : f.title ?? f.id }), f.detail ? el('span', { className: 'forensic__detail', text: f.detail }) : null),
        el('span', { className: 'mono', text: f.evidence || '—' }), f.technique ?? '—']))
      : none('Sin hallazgos.')),
    section('Autenticación', table('SPF, DKIM y DMARC', ['Mecanismo', 'Estado', 'Resultado', 'Detalle'],
      ['spf', 'dkim', 'dmarc'].map((k) => [k.toUpperCase(), AUTH_STATE.get(doc.auth[k].state) ?? doc.auth[k].state, doc.auth[k].result ?? '—', doc.auth[k].detail ?? '—']))),
    section('Cronología',
      el('p', { text: `Fecha del correo: ${doc.timeline.date ?? 'sin cabecera Date'}` }),
      doc.timeline.hops.length
        ? table('Saltos Received en orden de llegada', ['#', 'Desde', 'Por', 'IP', 'Fecha', 'UTC', '¿Atrás en el tiempo?'], doc.timeline.hops.map((h, i) => [
          String(i + 1), h.from ?? '—', h.by ?? '—', h.ip ?? '—', h.date ?? '—', h.utc ?? '—', h.backwards ? 'Sí: antes que el salto anterior' : 'No']))
        : none('Sin datos: no hay cabeceras Received.')),
    section('IOCs', ...(doc.iocs.length
      ? doc.iocs.map((g) => el('div', { className: 'forensic__iocs' }, el('h3', { text: `${g.label} (${g.items.length})` }),
        el('ul', {}, ...g.items.map((i) => el('li', { className: 'mono', text: i })))))
      : [none('Sin IOCs.')])),
    section('Adjuntos', doc.attachments.length
      ? table('Adjuntos', ['Nombre', 'Tipo declarado', 'Tipo real', 'Tamaño', 'Hashes', 'Visto por dentro'], doc.attachments.map((a) => [
        el('span', { className: 'mono', text: a.name ?? '—' }), a.declaredType ?? '—', a.realType ?? '—', a.size != null ? `${a.size} bytes` : '—',
        el('span', { className: 'mono forensic__hashes', text: [['SHA-256', a.sha256], ['SHA-1', a.sha1], ['MD5', a.md5]].filter(([, x]) => x).map(([k, x]) => `${k} ${x}`).join('\n') || 'Sin hash' }),
        a.seen]))
      : none('Sin adjuntos.')),
    section('URLs', ...(doc.urls.items.length
      ? [table('URLs y su cadena de saltos', ['URL', 'Destino final', 'Saltos', 'Cadena'], doc.urls.items.map((u) => [
        el('span', { className: 'mono', text: u.url }), el('span', { className: 'mono', text: u.final ?? '—' }), String(u.hops), el('span', { className: 'mono', text: u.chain })])),
      doc.urls.total > doc.urls.items.length ? none(`Se muestran ${doc.urls.items.length} de ${doc.urls.total}.`) : null]
      : [none('Sin URLs.')])),
    doc.notes != null ? section('Notas del analista', el('p', { className: 'forensic__notes', text: doc.notes })) : null,
    section('Límites', el('p', { text: doc.limits })),
  ];
  return el('div', { className: 'forensic' },
    el('header', { className: 'forensic__head' },
      el('h1', { text: 'Informe forense · PhishLens' }),
      el('p', { className: 'forensic__hint', text: 'Para guardarlo en PDF, elige «Guardar como PDF» como destino en el diálogo de impresión.' })),
    ...sections,
    el('p', { className: 'forensic__footer mono', text: `SHA-256 ${doc.identification.sha256 ?? 'no disponible'}` }));
}
