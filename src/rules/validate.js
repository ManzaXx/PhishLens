// Validador de reglas propias (spec 3.0, §5.1 y §6). El fichero se valida entero antes de aceptar nada.
// Listas cerradas de campos y operadores, topes fijos y sin expresiones regulares construidas con texto
// del usuario. Las reglas que salen de aquí son objetos nuevos con solo las claves conocidas.
import { CATEGORIES } from '../core/finding.js';
import { TECHNIQUES } from '../data/mitre.js';

export const RULES_LIMITS = Object.freeze({ fileBytes: 200 * 1024, rules: 100, depth: 4, conditions: 20, values: 200 });
const MAX_ERRORS = 50;

export const HEADER_FIELDS = Object.freeze([
  'from', 'to', 'cc', 'reply-to', 'return-path', 'sender', 'subject', 'date', 'message-id', 'x-mailer',
  'user-agent', 'x-originating-ip', 'x-priority', 'importance', 'list-unsubscribe', 'authentication-results',
  'received-spf', 'x-spam-status', 'x-ms-exchange-organization-scl', 'content-type',
]);

export const LIST_FIELDS = Object.freeze([
  'link.domain', 'link.url', 'attachment.name', 'attachment.extension', 'attachment.type', 'attachment.sha256', 'finding.id',
]);

export const FIELD_NAMES = Object.freeze([
  'subject', 'sender.address', 'sender.domain', 'sender.display', 'reply-to.domain', 'return-path.domain',
  ...LIST_FIELDS.filter((f) => f !== 'finding.id'), 'body.text', 'finding.id',
  ...HEADER_FIELDS.map((h) => `header:${h}`),
]);

export const OPERATORS = Object.freeze(['equals', 'contains', 'starts-with', 'ends-with', 'in', 'not-in', 'exists', 'count-gte']);

const FIELD_SET = new Set(FIELD_NAMES);
const LIST_SET = new Set(LIST_FIELDS);
const OP_SET = new Set(OPERATORS);
const TEXT_OPS = new Set(['equals', 'contains', 'starts-with', 'ends-with']);
const SEVERITIES = new Set(['low', 'medium', 'high']);
const CATEGORY_SET = new Set(CATEGORIES);
const RULE_KEYS = new Set(['id', 'title', 'detail', 'severity', 'category', 'technique', 'when']);
const LEAF_KEYS = new Set(['field', 'op', 'value']);
const GROUPS = ['all', 'any', 'not'];
const ID = /^[a-z0-9.-]{3,64}$/;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const show = (v) => String(typeof v === 'string' ? v : JSON.stringify(v)).slice(0, 60);

/** Texto para comparar: Unicode NFKC y minúsculas. */
export const normalize = (v) => String(v).normalize('NFKC').toLowerCase();

/** «Regla 3, `when.all[1].op`: motivo», o «Fichero, `ruta`: motivo». */
export function formatRuleError({ rule, path, reason }) {
  const who = rule == null ? 'Fichero' : `Regla ${rule}`;
  return path ? `${who}, \`${path}\`: ${reason}` : `${who}: ${reason}`;
}

function checkLeaf(node, path, err) {
  for (const key of Object.keys(node)) if (!LEAF_KEYS.has(key)) err(`${path}.${key}`, `«${show(key)}» no es una clave admitida`);
  const { field, op } = node;
  if (typeof field !== 'string' || !FIELD_SET.has(field)) return err(`${path}.field`, `«${show(field)}» no es un campo admitido`);
  if (typeof op !== 'string' || !OP_SET.has(op)) return err(`${path}.op`, `«${show(op)}» no es un operador admitido`);
  const value = node.value;
  if (op === 'exists') {
    if (has(node, 'value')) return err(`${path}.value`, 'exists no lleva value');
    return { field, op };
  }
  if (op === 'count-gte') {
    if (!LIST_SET.has(field)) return err(`${path}.op`, 'count-gte solo sirve para campos de lista (enlaces, adjuntos o hallazgos)');
    if (!Number.isInteger(value) || value < 0) return err(`${path}.value`, 'tiene que ser un número entero de 0 o más');
    return { field, op, value };
  }
  if (op === 'in' || op === 'not-in') {
    if (!Array.isArray(value) || !value.length) return err(`${path}.value`, 'tiene que ser una lista de textos');
    if (value.length > RULES_LIMITS.values) return err(`${path}.value`, `más de ${RULES_LIMITS.values} valores`);
    const bad = value.findIndex((v) => typeof v !== 'string' || !v);
    if (bad !== -1) return err(`${path}.value[${bad}]`, 'tiene que ser un texto no vacío');
    return { field, op, value: value.map(normalize) };
  }
  if (TEXT_OPS.has(op) && (typeof value !== 'string' || !value)) return err(`${path}.value`, 'tiene que ser un texto no vacío');
  return { field, op, value: normalize(value) };
}

/** Copia validada de una condición; null si tiene errores (ya anotados). */
function checkNode(node, path, depth, counter, err) {
  if (!isObj(node)) return err(path, 'tiene que ser una condición {field, op, value} o un grupo all, any o not');
  const groups = GROUPS.filter((g) => has(node, g));
  if (!groups.length) {
    counter.n++;
    return checkLeaf(node, path, err);
  }
  if (groups.length > 1 || Object.keys(node).length > 1) {
    return err(path, 'cada grupo lleva una sola de all, any o not, sin más claves');
  }
  const [group] = groups;
  if (depth + 1 > RULES_LIMITS.depth) return err(path, `más de ${RULES_LIMITS.depth} niveles de all, any o not`);
  const inner = node[group];
  if (group === 'not') {
    if (!isObj(inner)) return err(`${path}.not`, 'not lleva una sola condición, no una lista');
    const child = checkNode(inner, `${path}.not`, depth + 1, counter, err);
    return child && { not: child };
  }
  if (!Array.isArray(inner)) return err(`${path}.${group}`, 'tiene que ser una lista de condiciones');
  if (!inner.length) return err(`${path}.${group}`, 'la lista está vacía');
  const out = [];
  for (let i = 0; i < inner.length; i++) {
    if (counter.n > RULES_LIMITS.conditions) break;
    out.push(checkNode(inner[i], `${path}.${group}[${i}]`, depth + 1, counter, err));
  }
  return out.every(Boolean) && out.length === inner.length ? { [group]: out } : null;
}

function checkRule(raw, err, ids) {
  if (!isObj(raw)) return err('', 'tiene que ser un objeto');
  let ok = true;
  const fail = (path, reason) => { ok = false; return err(path, reason); };
  for (const key of Object.keys(raw)) if (!RULE_KEYS.has(key)) fail(key, `«${show(key)}» no es una clave admitida`);
  const { id, title, severity, category } = raw;
  if (typeof id !== 'string' || !ID.test(id)) fail('id', 'tiene que tener de 3 a 64 caracteres de a-z, 0-9, punto o guion');
  else if (ids.has(id)) fail('id', `«${id}» está repetido`);
  else ids.add(id);
  if (typeof title !== 'string' || !title.trim() || title.length > 120) fail('title', 'tiene que ser un texto de 1 a 120 caracteres');
  const detail = has(raw, 'detail') ? raw.detail : '';
  if (typeof detail !== 'string' || detail.length > 300) fail('detail', 'tiene que ser un texto de 300 caracteres como mucho');
  if (typeof severity !== 'string' || !SEVERITIES.has(severity)) fail('severity', 'tiene que ser low, medium o high');
  if (typeof category !== 'string' || !CATEGORY_SET.has(category)) fail('category', `tiene que ser una de: ${CATEGORIES.join(', ')}`);
  const technique = has(raw, 'technique') ? raw.technique : null;
  if (technique !== null && (typeof technique !== 'string' || !has(TECHNIQUES, technique))) fail('technique', `«${show(technique)}» no es una técnica ATT&CK conocida`);
  const counter = { n: 0 };
  const when = has(raw, 'when') ? checkNode(raw.when, 'when', 0, counter, fail) : fail('when', 'falta la condición');
  if (counter.n > RULES_LIMITS.conditions) fail('when', `más de ${RULES_LIMITS.conditions} condiciones en la regla`);
  if (!ok || !when) return null;
  return { id, title, detail, severity, category, technique, when };
}

/**
 * Valida un fichero de reglas. Devuelve las reglas normalizadas o todos los errores (hasta 50),
 * cada uno con su regla (desde 1, o null si es del fichero), su ruta y su motivo.
 */
export function validateRules(text) {
  const errors = [];
  const fileErr = (path, reason) => { errors.push({ rule: null, path, reason }); return { ok: false, errors }; };
  if (typeof text !== 'string') return fileErr('', 'no es JSON válido');
  if (text.length > RULES_LIMITS.fileBytes || new TextEncoder().encode(text).length > RULES_LIMITS.fileBytes) {
    return fileErr('', 'el fichero pasa de 200 KB');
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return fileErr('', 'no es JSON válido');
  }
  if (!isObj(data)) return fileErr('', 'tiene que ser un objeto con phishlens y rules');
  for (const key of Object.keys(data)) if (key !== 'phishlens' && key !== 'rules') fileErr(key, `«${show(key)}» no es una clave admitida`);
  if (data.phishlens !== 'rules/1') fileErr('phishlens', 'tiene que ser «rules/1»');
  if (!Array.isArray(data.rules)) fileErr('rules', 'tiene que ser una lista');
  else if (data.rules.length > RULES_LIMITS.rules) fileErr('rules', `más de ${RULES_LIMITS.rules} reglas`);
  if (errors.length) return { ok: false, errors };

  const rules = [];
  const ids = new Set();
  for (let i = 0; i < data.rules.length && errors.length < MAX_ERRORS; i++) {
    const err = (path, reason) => {
      if (errors.length < MAX_ERRORS) errors.push({ rule: i + 1, path, reason });
      return null;
    };
    const rule = checkRule(data.rules[i], err, ids);
    if (rule) rules.push(rule);
  }
  return errors.length ? { ok: false, errors } : { ok: true, rules };
}
