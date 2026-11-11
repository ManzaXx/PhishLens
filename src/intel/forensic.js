// Informe forense (spec 3.0, §4): el mismo contenido para el PDF y para el JSON, sin DOM. Los IOCs y las
// evidencias van defanged; el texto se pinta luego con textContent. El JSON lleva reportSha256: el
// SHA-256 de su propio texto (JSON.stringify con 2 espacios) sin ese campo, que va el último.
import { sha256 } from '../lib/sha256.js';
import { sha1 } from '../lib/sha1.js';
import { md5 } from '../lib/md5.js';
import { defang, IOC_SECTIONS, PLAIN } from './ioc.js';
import { analyzeUrl, chainText } from './url.js';
import { SEVERITY_ORDER } from '../core/finding.js';

export const MAX_NOTES = 5000;
export const MAX_URLS = 100;
export const LIMITS_TEXT = 'PhishLens no resuelve DNS, no consulta reputación ni visita enlaces, y no descomprime los flujos de los PDF. Más en docs/limitations.md.';

const str = (v) => (v == null ? null : String(v));
const list = (v) => (Array.isArray(v) ? v : []);
// Traductor por defecto: deja el texto en español (intel/ no importa i18n; la interfaz pasa el suyo).
const KEEP = (code, params, fallback) => fallback;
const LOCALES = { es: 'es-ES', en: 'en-GB' };

const iso = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString() : null);

function identification(source, analyzedAt, version, lang) {
  const base = { name: str(source?.name), size: null, sha256: null, sha1: null, md5: null, hashOf: 'text' };
  if (source?.kind === 'saved') {
    Object.assign(base, { sha256: str(source.sha256) });
  } else if (source?.bytes instanceof Uint8Array) {
    // Los bytes del fichero tal cual: lo que da sha256sum, aunque lleve BOM o no sea UTF-8.
    const bytes = source.bytes;
    Object.assign(base, { size: bytes.length, sha256: sha256(bytes), sha1: sha1(bytes), md5: md5(bytes), hashOf: 'file' });
  } else {
    const text = String(source?.text ?? '');
    const bytes = new TextEncoder().encode(text);
    Object.assign(base, { size: bytes.length, sha256: sha256(text), sha1: sha1(bytes), md5: md5(bytes) });
  }
  return {
    ...base,
    analyzedAt: { utc: analyzedAt.toISOString(), local: analyzedAt.toLocaleString(LOCALES[lang] ?? LOCALES.es, { timeZoneName: 'short' }) },
    version: String(version),
    savedAt: source?.kind === 'saved' ? str(source.savedAt) : null,
  };
}

function findings(report) {
  const rank = (f) => {
    const i = SEVERITY_ORDER.indexOf(f?.severity);
    return i === -1 ? SEVERITY_ORDER.length : i;
  };
  // sort es estable: dentro de cada gravedad se mantiene el orden del motor.
  return list(report.findings).filter((f) => f && typeof f === 'object').sort((a, b) => rank(a) - rank(b)).map((f) => {
    const t = f.mitre ?? list(f.techniques)[0] ?? null;
    return {
      id: str(f.id), severity: str(f.severity), title: str(f.title), detail: str(f.detail),
      evidence: f.evidence ? defang(f.evidence) : '',
      technique: t?.id ? `${t.id} · ${t.name ?? ''}`.trim() : null,
      custom: f.custom === true,
    };
  });
}

function auth(report) {
  const out = {};
  for (const k of ['spf', 'dkim', 'dmarc']) {
    const a = report.auth?.[k] ?? {};
    out[k] = { state: str(a.state) ?? 'none', result: str(a.result), detail: str(a.detail) };
  }
  return out;
}

function timeline(report) {
  let prev = null;
  const hops = list(report.email?.route).map((h) => {
    const time = Number.isFinite(h?.time) ? h.time : null;
    const backwards = time !== null && prev !== null && time < prev;
    if (time !== null) prev = time;
    return { from: str(h?.from), by: str(h?.by), ip: str(h?.ip), date: str(h?.date), utc: iso(time), backwards };
  });
  return { date: str(report.email?.date), hops };
}

function iocs(report, tr) {
  return IOC_SECTIONS.map(([type, label]) => ({ type, label: tr(`ioc.section.${type}`, {}, label), items: list(report.iocs?.[type]).map((v) => (PLAIN.has(type) ? String(v) : defang(v))) }))
    .filter((g) => g.items.length);
}

/** Lo visto dentro de un adjunto, en una frase. */
// Lo visto dentro de un adjunto, en una frase. Los motivos de bajo nivel (zip.reason, ole.reason) son
// textos técnicos cortos que no se traducen (docs/limitations.md).
function seen(i, tr) {
  const say = (code, params, text) => tr(`report.forensic.seen.${code}`, params, text);
  if (!i) return say('none', {}, 'No se ha mirado.');
  if (i.partial) return say('partial', {}, 'No se ha mirado dentro: el adjunto está recortado o no se pudo leer entero.');
  const parts = [];
  if (i.zip) {
    if (!i.zip.ok) parts.push(say('zip-bad', { reason: i.zip.reason }, `ZIP que no se pudo leer: ${i.zip.reason}.`));
    else {
      const locked = list(i.zip.entries).filter((e) => e.encrypted).length;
      const names = list(i.zip.entries).slice(0, 20).map((e) => e.name).join(', ');
      const count = list(i.zip.entries).length;
      const params = {
        count,
        more: i.zip.truncated ? { key: 'report.forensic.seen.or-more' } : '',
        locked: locked ? { code: 'report.forensic.seen.locked', params: { n: locked } } : '',
        vba: i.zip.vbaProject ? { key: 'report.forensic.seen.with-vba' } : '',
        names: names ? `: ${names}` : '',
      };
      parts.push(say('zip', params, `ZIP con ${count}${i.zip.truncated ? ' o más' : ''} entradas${locked ? `, ${locked} cifradas` : ''}${i.zip.vbaProject ? ', con macros VBA' : ''}${names ? `: ${names}` : ''}.`));
    }
  }
  if (i.ole) {
    parts.push(!i.ole.ok ? say('ole-bad', { reason: i.ole.reason }, `Documento que no se pudo leer: ${i.ole.reason}.`)
      : i.ole.hasVba ? say('vba', {}, 'Lleva macros VBA.') : say('no-macros', {}, 'Sin macros.'));
  }
  if (i.pdf) {
    const tokens = list(i.pdf.tokens).map((t) => `/${t}`).join(', ');
    parts.push(tokens ? say('pdf-active', { tokens }, `Instrucciones activas: ${tokens}.`) : say('pdf-quiet', {}, 'Sin instrucciones activas en el texto visible.'));
    if (i.pdf.compressedStreams) parts.push(say('pdf-streams', { n: i.pdf.compressedStreams }, `${i.pdf.compressedStreams} flujos comprimidos sin mirar.`));
  }
  if (i.html) {
    const markers = list(i.html.markers).join(', ');
    parts.push(i.html.suspicious ? say('html-smuggling', { markers }, `Crea archivos desde un script: ${markers}.`) : say('html-quiet', {}, 'Sin señales de que fabrique archivos.'));
  }
  return parts.join(' ') || say('nothing', {}, 'Nada que señalar.');
}

function attachments(report, tr) {
  const realType = (i) => (i?.realType ? tr(`filetype.${i.realType}`, {}, str(i.realLabel)) : str(i?.realLabel));
  return list(report.email?.attachments).map((a) => ({
    name: str(a?.filename), declaredType: str(a?.contentType), realType: realType(a?.inspection), size: Number.isFinite(a?.size) ? a.size : null,
    sha256: str(a?.sha256), sha1: str(a?.sha1), md5: str(a?.md5), seen: seen(a?.inspection, tr),
  }));
}

function urls(report) {
  const hrefs = [...new Set(list(report.email?.links).map((l) => l?.href).filter((h) => typeof h === 'string' && h))];
  const items = hrefs.slice(0, MAX_URLS).map((href) => {
    let analysis = null;
    try { analysis = analyzeUrl(href); } catch { analysis = null; }
    return {
      url: defang(href),
      final: analysis ? defang(analysis.final) : null,
      hops: analysis ? analysis.hops.length : 0,
      chain: analysis ? defang(chainText(analysis)).replace(/ → (http)/gi, ' → hxxp') : defang(href),
    };
  });
  return { total: hrefs.length, items };
}

/**
 * @param {{report: object, source: {kind: 'live', name: string|null, text: string, bytes?: Uint8Array} | {kind: 'saved', name: string|null, sha256: string, savedAt: string},
 *   analyzedAt: Date, version: string, notes?: string, lang?: 'es'|'en', tr?: (code, params, fallback) => string}} input
 * `report` llega ya en el idioma del informe (la interfaz lo localiza); `tr` traduce lo que se escribe aquí.
 */
export function forensicReport({ report, source, analyzedAt, version, notes = '', lang = 'es', tr = KEEP }) {
  const r = report ?? {};
  const note = String(notes ?? '').slice(0, MAX_NOTES);
  return {
    tool: 'PhishLens',
    format: 'forensic/1',
    lang: lang === 'en' ? 'en' : 'es',
    identification: identification(source, analyzedAt, version, lang),
    verdict: { level: str(r.level), label: str(r.label), score: Number.isFinite(r.score) ? r.score : null, confidence: str(r.confidence?.level), headline: str(r.verdict?.headline) },
    findings: findings(r),
    auth: auth(r),
    timeline: timeline(r),
    iocs: iocs(r, tr),
    attachments: attachments(r, tr),
    urls: urls(r),
    notes: note.trim() ? note : null,
    limits: tr('report.forensic.limits', {}, LIMITS_TEXT),
  };
}

/** Texto JSON del informe con reportSha256 al final. */
export function forensicJson(doc) {
  const { reportSha256, ...body } = doc;
  const text = JSON.stringify(body, null, 2);
  return JSON.stringify({ ...body, reportSha256: sha256(text) }, null, 2);
}

/** ¿El JSON es un informe forense sin tocar? Quita reportSha256, rehace el texto y compara. */
export function verifyForensicJson(text) {
  let value;
  try { value = JSON.parse(text); } catch { return false; }
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.reportSha256 !== 'string') return false;
  const { reportSha256, ...body } = value;
  return sha256(JSON.stringify(body, null, 2)) === reportSha256;
}

/** phishlens-forense-AAAA-MM-DD.json, con la fecha en UTC. */
export const forensicFileName = (date) => `phishlens-forense-${date.toISOString().slice(0, 10)}.json`;
