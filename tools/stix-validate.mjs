// Validador STIX 2.1 propio (spec 2.3, §5.4): lo justo para los objetos que exporta PhishLens.
// Uso: node tools/stix-validate.mjs bundle.json → imprime los errores y sale con 1 si hay alguno.
// Lo usan también los tests y el fuzzing. Nunca lanza: todo problema es un mensaje.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const ID = new RegExp(`^([a-z0-9-]+)--${UUID}$`);
const STAMP_MS = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const STAMP = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;

const SDO = new Set(['indicator', 'attack-pattern', 'campaign', 'relationship']);
const REQUIRED = {
  indicator: ['pattern', 'pattern_type', 'valid_from'],
  'attack-pattern': ['name'],
  campaign: ['name'],
  relationship: ['relationship_type', 'source_ref', 'target_ref'],
  'domain-name': ['value'],
  url: ['value'],
  'ipv4-addr': ['value'],
  'ipv6-addr': ['value'],
  'email-addr': ['value'],
  'email-message': ['is_multipart'],
  file: [],
};
const KNOWN = new Set(Object.keys(REQUIRED));

// Patrones de los tipos que exporta PhishLens. Dentro de las comillas solo valen \' y \\ como escapes.
const STRING = "'(?:[^'\\\\]|\\\\['\\\\])*'";
const PATTERNS = [
  new RegExp(`^\\[(url|domain-name|ipv4-addr|ipv6-addr|email-addr):value = ${STRING}\\]$`),
  /^\[file:hashes\.'(SHA-256|SHA-1|MD5)' = '[0-9a-f]+'\]$/,
];

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Todas las referencias (_ref y _refs) de un objeto, también dentro de listas de objetos. */
function refsOf(value, out = []) {
  if (Array.isArray(value)) for (const v of value) refsOf(v, out);
  else if (isObj(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (k.endsWith('_ref')) out.push([k, v]);
      else if (k.endsWith('_refs')) for (const r of Array.isArray(v) ? v : [v]) out.push([k, r]);
      else refsOf(v, out);
    }
  }
  return out;
}

/** @returns {string[]} errores; vacío si el bundle es válido. */
export function validateBundle(bundle) {
  const errors = [];
  if (!isObj(bundle) || bundle.type !== 'bundle') return ['no es un bundle (type debe ser «bundle»)'];
  if (!/^bundle--/.test(String(bundle.id)) || !ID.test(String(bundle.id))) errors.push(`bundle: id mal formado (${bundle.id})`);
  if (!Array.isArray(bundle.objects) || !bundle.objects.length) return [...errors, 'bundle: objects debe ser una lista con algún objeto'];

  const ids = new Set();
  for (const [i, o] of bundle.objects.entries()) {
    if (!isObj(o)) {
      errors.push(`objeto ${i}: no es un objeto`);
      continue;
    }
    const where = `${o.type ?? '?'} ${o.id ?? i}`;
    if (!KNOWN.has(o.type)) {
      errors.push(`${where}: tipo desconocido`);
      continue;
    }
    const m = ID.exec(String(o.id));
    if (!m || m[1] !== o.type) errors.push(`${where}: id mal formado o de otro tipo`);
    if (ids.has(o.id)) errors.push(`${where}: id repetido`);
    ids.add(o.id);
    if (o.spec_version !== '2.1') errors.push(`${where}: spec_version debe ser «2.1»`);
    for (const key of REQUIRED[o.type]) if (o[key] === undefined || o[key] === '') errors.push(`${where}: falta ${key}`);
    if (SDO.has(o.type)) {
      for (const key of ['created', 'modified']) if (!STAMP_MS.test(String(o[key]))) errors.push(`${where}: ${key} debe ser un timestamp UTC con milisegundos`);
    }
    if (o.type === 'file' && !isObj(o.hashes) && !o.name) errors.push(`${where}: un file necesita hashes o name`);
    if (o.type === 'email-message' && typeof o.is_multipart !== 'boolean') errors.push(`${where}: is_multipart debe ser booleano`);
    if (o.type === 'email-message' && o.date !== undefined && !STAMP.test(String(o.date))) errors.push(`${where}: date no es un timestamp`);
    if (o.type === 'indicator') {
      if (o.pattern_type !== 'stix') errors.push(`${where}: pattern_type debe ser «stix»`);
      if (!PATTERNS.some((re) => re.test(String(o.pattern)))) errors.push(`${where}: pattern mal formado o de un tipo no admitido`);
      if (!STAMP.test(String(o.valid_from))) errors.push(`${where}: valid_from no es un timestamp`);
    }
    if (o.type === 'attack-pattern') {
      for (const ref of o.external_references ?? []) if (!isObj(ref) || !ref.source_name) errors.push(`${where}: external_references sin source_name`);
    }
  }
  for (const o of bundle.objects) {
    if (!isObj(o) || !KNOWN.has(o.type)) continue;
    for (const [key, ref] of refsOf(o)) {
      if (!ids.has(ref)) errors.push(`${o.type} ${o.id}: ${key} apunta a ${ref}, que no existe en el bundle`);
    }
  }
  return errors;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const file = process.argv[2];
  if (!file) {
    console.error('Uso: node tools/stix-validate.mjs bundle.json');
    process.exit(2);
  }
  let errors;
  try {
    errors = validateBundle(JSON.parse(readFileSync(file, 'utf8')));
  } catch (e) {
    errors = [`no se pudo leer ${file}: ${e.message}`];
  }
  for (const e of errors) console.log(e);
  console.log(errors.length ? `${errors.length} errores` : 'Bundle STIX 2.1 válido');
  process.exit(errors.length ? 1 : 0);
}
