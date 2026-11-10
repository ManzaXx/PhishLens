// Historial (spec 3.0, §2.2 y §6). El informe que se guarda no permite reconstruir el correo, y todo lo
// que se lee de IndexedDB o de un fichero importado se valida y se copia antes de usarlo: puede venir
// manipulado por otra pestaña, una extensión o un fichero viejo.
import { LEVELS } from '../core/scoring.js';
import { SEVERITY_ORDER } from '../core/finding.js';

export const MAX_STRING = 10000;
export const MAX_ENTRY_BYTES = 1024 * 1024;
const MAX_DEPTH = 16;
const MAX_FINDINGS = 500;
const BODY_EXCERPT = 40;
// Detectores cuya evidencia copia trozos del cuerpo del correo (Ruling 2 del plan del PR10).
const BODY_DETECTORS = new Set(['language', 'html']);
const BANNED = new Set(['__proto__', 'constructor', 'prototype']);
const KINDS = new Set(['eml', 'text', 'url']);
const LEVEL_SET = new Set(LEVELS.map((l) => l.level));
const SEVERITIES = new Set(SEVERITY_ORDER);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z$/;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const cut = (s, n) => (s.length > n ? s.slice(0, n) : s);

/** Copia JSON limpia: solo objetos planos, listas y primitivos; sin claves peligrosas; cadenas recortadas. */
function clean(value, depth, limit) {
  if (depth > MAX_DEPTH) throw new Error('demasiado anidado');
  if (typeof value === 'string') {
    if (limit === 'reject' && value.length > MAX_STRING) throw new Error('una cadena es demasiado larga');
    return cut(value, MAX_STRING);
  }
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.map((v) => clean(v, depth + 1, limit));
  if (isObj(value)) {
    const out = {};
    for (const key of Object.keys(value)) {
      if (BANNED.has(key) || value[key] === undefined || typeof value[key] === 'function') continue;
      out[key] = clean(value[key], depth + 1, limit);
    }
    return out;
  }
  return null; // Uint8Array, Map, fechas…: no se guardan.
}

/** Informe sin el cuerpo, las cabeceras en bruto ni los bytes de los adjuntos. No toca el original. */
export function slimReport(report) {
  const copy = clean(report ?? {}, 0, 'cut');
  if (isObj(copy.email)) {
    delete copy.email.text;
    delete copy.email.html;
    delete copy.email.raw;
    delete copy.email.rawHeaders;
    if (Array.isArray(copy.email.attachments)) for (const a of copy.email.attachments) if (isObj(a)) delete a.bytes;
  }
  cutBodyEvidence(copy);
  return copy;
}

// Los hallazgos aparecen copiados en varios sitios (findings, verdict.top…): se recortan todos.
function cutBodyEvidence(value) {
  if (Array.isArray(value)) for (const v of value) cutBodyEvidence(v);
  else if (isObj(value)) {
    if (BODY_DETECTORS.has(value.detector) && typeof value.evidence === 'string') value.evidence = cut(value.evidence, BODY_EXCERPT);
    for (const v of Object.values(value)) cutBodyEvidence(v);
  }
}

/** JSON.parse que descarta __proto__, constructor y prototype. Lanza si el texto no es JSON. */
export function safeParse(text) {
  return JSON.parse(String(text), (key, value) => (BANNED.has(key) ? undefined : value));
}

const fail = (error) => ({ ok: false, error });

/** Valida un registro de lote (`batches`): ids, fecha, listas de hashes y campañas. Devuelve una copia limpia. */
export function validateBatch(value) {
  if (!isObj(value)) return fail('el lote no es un objeto');
  let b;
  try {
    b = clean(value, 0, 'reject');
  } catch (e) {
    return fail(`lote: ${e.message}`);
  }
  const texts = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string');
  if (typeof b.id !== 'string' || !b.id) return fail('id: falta');
  if (typeof b.savedAt !== 'string' || !ISO.test(b.savedAt)) return fail('savedAt: no es una fecha ISO');
  if (!texts(b.emails)) return fail('emails: lista de textos');
  if (!Array.isArray(b.campaigns) || b.campaigns.length > 200) return fail('campaigns: lista de 200 como mucho');
  for (const [i, c] of b.campaigns.entries()) {
    if (!isObj(c) || typeof c.name !== 'string' || !texts(c.emails) || !texts(c.reasons ?? [])) return fail(`campaigns[${i}]: campaña mal formada`);
  }
  return { ok: true, batch: b };
}

/** Valida una entrada del historial y devuelve una copia nueva y limpia. */
export function validateEntry(value) {
  if (!isObj(value)) return fail('la entrada no es un objeto');
  let entry;
  try {
    entry = clean(value, 0, 'reject');
  } catch (e) {
    return fail(`report: ${e.message}`);
  }
  if (JSON.stringify(entry).length > MAX_ENTRY_BYTES) return fail('report: la entrada pasa de 1 MB');
  if (typeof entry.id !== 'string' || !UUID.test(entry.id)) return fail('id: no es un UUID');
  if (typeof entry.savedAt !== 'string' || !ISO.test(entry.savedAt) || Number.isNaN(Date.parse(entry.savedAt))) return fail('savedAt: no es una fecha ISO');
  if (typeof entry.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(entry.version)) return fail('version: formato x.y.z');
  if (!KINDS.has(entry.kind)) return fail('kind: debe ser eml, text o url');
  if (typeof entry.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(entry.sha256)) return fail('sha256: 64 caracteres hexadecimales');
  if (entry.name != null && (typeof entry.name !== 'string' || entry.name.length > 260)) return fail('name: texto de 260 caracteres como mucho');
  const r = entry.report;
  if (!isObj(r)) return fail('report: no es un objeto');
  if (!LEVEL_SET.has(r.level)) return fail('report.level: nivel desconocido');
  if (typeof r.score !== 'number' || r.score < 0 || r.score > 100) return fail('report.score: debe estar entre 0 y 100');
  if (!Array.isArray(r.findings) || r.findings.length > MAX_FINDINGS) return fail('report.findings: lista de 500 como mucho');
  for (const [i, f] of r.findings.entries()) {
    if (!isObj(f) || typeof f.id !== 'string' || !SEVERITIES.has(f.severity)) return fail(`report.findings[${i}]: hallazgo mal formado`);
  }
  if (r.email != null && !isObj(r.email)) return fail('report.email: no es un objeto');
  // Las vistas y la búsqueda recorren estas listas: si vienen mal formadas, la entrada no entra.
  if (!Array.isArray(r.techniques)) return fail('report.techniques: no es una lista');
  const v = r.verdict;
  if (!isObj(v) || typeof v.headline !== 'string' || !Array.isArray(v.top) || !Array.isArray(v.steps)) return fail('report.verdict: veredicto mal formado');
  if (r.auth != null && !isObj(r.auth)) return fail('report.auth: no es un objeto');
  if (r.categories != null && !Array.isArray(r.categories)) return fail('report.categories: no es una lista');
  if (r.iocs != null) {
    if (!isObj(r.iocs)) return fail('report.iocs: no es un objeto');
    for (const [k, v] of Object.entries(r.iocs)) {
      if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) return fail(`report.iocs.${k}: lista de textos`);
    }
  }
  // Lo que llega de un fichero o de otra pestaña tampoco puede meter el cuerpo del correo.
  return { ok: true, entry: { ...entry, name: entry.name ?? null, report: slimReport(r) } };
}
