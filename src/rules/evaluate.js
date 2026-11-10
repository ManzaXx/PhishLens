// Motor de reglas propias (spec 3.0, §5.1 y §5.2). Los campos se leen con un mapa explícito de
// funciones: nunca obj[texto del usuario]. Cada valor se normaliza (NFKC y minúsculas) una vez por
// análisis y se compara con operadores de una lista cerrada, sin expresiones regulares.
import { parseUrl } from '../parser/url.js';
import { htmlToText } from '../parser/html.js';
import { finding } from '../core/finding.js';
import { technique } from '../data/mitre.js';
import { LIMITS } from '../lib/limits.js';
import { HEADER_FIELDS, LIST_FIELDS, normalize } from './validate.js';

const EVIDENCE_MAX = 200;
const LIST_SET = new Set(LIST_FIELDS);

const str = (v) => (typeof v === 'string' && v ? v : null);
const domainOf = (address) => {
  const s = str(address);
  const at = s ? s.lastIndexOf('@') : -1;
  return at >= 0 && at < s.length - 1 ? s.slice(at + 1) : null;
};
const links = (e) => (Array.isArray(e?.links) ? e.links : []);
const attachments = (e) => (Array.isArray(e?.attachments) ? e.attachments : []);
const strings = (list) => list.filter((v) => typeof v === 'string' && v);
const extension = (name) => {
  const dot = name.lastIndexOf('.');
  return dot >= 0 && dot < name.length - 1 ? name.slice(dot + 1) : null;
};
const header = (name) => (e) => {
  const values = e?.headers instanceof Map ? e.headers.get(name) : null;
  return Array.isArray(values) ? strings(values) : [];
};

/** Nombre del campo → función (correo, hallazgos de PhishLens) → texto, lista de textos o null. */
export const FIELDS = new Map([
  ['subject', (e) => str(e?.subject)],
  ['sender.address', (e) => str(e?.from?.address)],
  ['sender.domain', (e) => str(e?.from?.domain)],
  ['sender.display', (e) => str(e?.from?.name)],
  ['reply-to.domain', (e) => str(e?.replyTo?.domain)],
  ['return-path.domain', (e) => domainOf(e?.returnPath)],
  ['link.domain', (e) => strings(links(e).map((l) => parseUrl(String(l?.href ?? ''))?.hostname ?? null))],
  ['link.url', (e) => strings(links(e).map((l) => l?.href))],
  ['attachment.name', (e) => strings(attachments(e).map((a) => a?.filename))],
  ['attachment.extension', (e) => strings(attachments(e).map((a) => (typeof a?.filename === 'string' ? extension(a.filename) : null)))],
  ['attachment.type', (e) => strings(attachments(e).map((a) => a?.contentType))],
  ['attachment.sha256', (e) => strings(attachments(e).map((a) => a?.sha256))],
  // Como el detector de lenguaje: el texto plano, o el texto del HTML si no hay parte de texto.
  ['body.text', (e) => str((String(e?.text ?? '').trim() ? String(e.text) : htmlToText(String(e?.html ?? ''))).slice(0, LIMITS.ruleBodyChars))],
  ['finding.id', (e, prior) => strings((Array.isArray(prior) ? prior : []).filter((f) => !f?.custom).map((f) => f?.id))],
  ...HEADER_FIELDS.map((h) => [`header:${h}`, header(h)]),
]);

/** Valores normalizados del campo, en lista (vacía si falta), con caché por análisis. */
function valuesOf(field, email, prior, cache) {
  if (cache.has(field)) return cache.get(field);
  const read = FIELDS.get(field);
  const raw = read ? read(email, prior) : null;
  const list = Array.isArray(raw) ? raw : raw == null ? [] : [raw];
  const out = list.map((v) => ({ raw: v, norm: normalize(v) }));
  cache.set(field, out);
  return out;
}

const TEXT_TESTS = {
  equals: (v, x) => v === x,
  contains: (v, x) => v.includes(x),
  'starts-with': (v, x) => v.startsWith(x),
  'ends-with': (v, x) => v.endsWith(x),
  in: (v, x) => x.includes(v),
  'not-in': (v, x) => !x.includes(v),
};

function leaf({ field, op, value }, email, prior, cache) {
  const values = valuesOf(field, email, prior, cache);
  if (op === 'exists') return values.length ? values[0].raw : null;
  if (op === 'count-gte') return LIST_SET.has(field) && values.length >= value ? String(values.length) : null;
  const check = Object.hasOwn(TEXT_TESTS, op) ? TEXT_TESTS[op] : null;
  if (!check) return null;
  const hit = values.find((v) => check(v.norm, value));
  return hit ? hit.norm : null;
}

/** Devuelve la evidencia (texto) si el nodo se cumple, o null. */
function node(n, email, prior, cache) {
  if (Array.isArray(n.all)) {
    let first = null;
    for (const child of n.all) {
      const ev = node(child, email, prior, cache);
      if (ev === null) return null;
      first ??= ev;
    }
    return first ?? '';
  }
  if (Array.isArray(n.any)) {
    for (const child of n.any) {
      const ev = node(child, email, prior, cache);
      if (ev !== null) return ev;
    }
    return null;
  }
  if (n.not) return node(n.not, email, prior, cache) === null ? '' : null;
  return leaf(n, email, prior, cache);
}

/** ¿Se cumple la regla? La evidencia es el primer valor que cumplió, recortado. */
export function evaluate(rule, email, prior = [], cache = new Map()) {
  const ev = node(rule.when, email, prior, cache);
  return { match: ev !== null, evidence: ev === null ? '' : String(ev).slice(0, EVIDENCE_MAX) };
}

/** Hallazgos «custom.<id>» de las reglas que se cumplen. `prior` son los hallazgos de PhishLens. */
export function customFindings(rules, email, prior = []) {
  const cache = new Map();
  const out = [];
  for (const rule of Array.isArray(rules) ? rules : []) {
    const { match, evidence } = evaluate(rule, email, prior, cache);
    if (!match) continue;
    const f = finding({
      id: `custom.${rule.id}`,
      detector: 'custom',
      severity: rule.severity,
      title: rule.title,
      detail: rule.detail ? `${rule.detail} Regla propia.` : 'Regla propia.',
      evidence,
      category: rule.category,
    });
    const t = rule.technique ? technique(rule.technique) : null;
    out.push({ ...f, techniques: t ? [t] : [], mitre: t, plain: rule.title, custom: true });
  }
  return out;
}
