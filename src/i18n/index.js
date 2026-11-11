// Idioma de la interfaz (spec 3.1): español o inglés. Diccionarios planos clave → texto con {param}.
// t() busca en el idioma activo, luego en español y si no, devuelve la clave. Los parámetros se
// sustituyen en una sola pasada: un valor del correo con llaves no se vuelve a interpolar.
import ES from './es.js';
import EN from './en.js';
import RULES_EN from './rules-en.js';

export const LANG_KEY = 'phishlens-lang';
export const LOCALE = Object.freeze({ es: 'es-ES', en: 'en-GB' });
const LANGS = new Set(['es', 'en']);

const toMap = (dict) => new Map(Object.entries(dict ?? {}));
const REAL = () => ({ es: toMap(ES), en: toMap({ ...EN, ...RULES_EN }) });
let dicts = REAL();
let lang = 'es';
const listeners = new Set();

/** Solo para tests: cambia los diccionarios (null vuelve a los de verdad). */
export function _setDictionaries(next) {
  dicts = next ? { es: toMap(next.es), en: toMap(next.en) } : REAL();
}

export const getLang = () => lang;

export function setLang(next) {
  if (!LANGS.has(next) || next === lang) return;
  lang = next;
  for (const fn of [...listeners]) fn(lang);
}

export function onLangChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Idioma guardado si es válido; si no, el del navegador (es* → es); si no, inglés. */
export function initialLang(stored, navigatorLanguage) {
  if (typeof stored === 'string' && LANGS.has(stored)) return stored;
  return typeof navigatorLanguage === 'string' && /^es\b/i.test(navigatorLanguage) ? 'es' : 'en';
}

const lookup = (key) => dicts[lang].get(key) ?? dicts.es.get(key);

function pick(key, params) {
  if (typeof params?.count === 'number') {
    const form = new Intl.PluralRules(LOCALE[lang]).select(params.count);
    const plural = lookup(`${key}.${form}`) ?? lookup(`${key}.other`);
    if (plural != null) return plural;
  }
  return lookup(key);
}

export function t(key, params) {
  const text = pick(key, params);
  if (text == null) return key;
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (all, name) => (Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : all));
}

// Plantilla inglesa de una clave del informe: con count, su plural; sin count, la clave o su «.one».
function englishTemplate(key, params) {
  const en = dicts.en;
  if (typeof params?.count === 'number') {
    const form = new Intl.PluralRules(LOCALE.en).select(params.count);
    return en.get(`${key}.${form}`) ?? en.get(`${key}.other`) ?? en.get(key) ?? null;
  }
  return en.get(key) ?? en.get(`${key}.one`) ?? null;
}

// Un parámetro {key} es una palabra que elige el detector: se traduce antes de sustituirla.
const resolveParam = (v) => (v && typeof v === 'object' && typeof v.key === 'string' ? t(v.key) : v);

/** Por qué tr() no puede usar la traducción inglesa de `key` (null si puede). */
export function trProblem(key, params) {
  const tpl = englishTemplate(key, params);
  if (tpl == null) return 'sin traducción';
  for (const [, name] of tpl.matchAll(/\{(\w+)\}/g)) {
    if (!params || !Object.prototype.hasOwnProperty.call(params, name) || params[name] == null) return `falta {${name}}`;
  }
  return null;
}

/**
 * Texto del informe en el idioma activo. En español, `fallback` (el texto del núcleo). En inglés, la
 * plantilla con sus parámetros; si falta la clave o algún parámetro, `fallback` entero, nunca media frase.
 */
export function tr(key, params, fallback) {
  if (lang === 'es' || trProblem(key, params)) return fallback;
  const tpl = englishTemplate(key, params);
  return tpl.replace(/\{(\w+)\}/g, (all, name) => String(resolveParam(params[name])));
}

/** Fecha en el idioma activo; '' si no es válida. */
export function fmtDate(date, options) {
  const d = date instanceof Date ? date : new Date(date);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString(LOCALE[lang], options);
}

/** Número en el idioma activo. En es-ES, toLocaleString no agrupa los de 4 cifras: el punto se pone a mano. */
export function fmtNumber(n) {
  if (lang === 'en') return Number(n).toLocaleString(LOCALE.en);
  const [int, dec] = String(n).split('.');
  const grouped = int.replace(/\B(?=(\d{3})+(?!\d))/g, '.');
  return dec ? `${grouped},${dec}` : grouped;
}
