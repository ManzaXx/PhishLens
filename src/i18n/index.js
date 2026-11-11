// Idioma de la interfaz (spec 3.1): español o inglés. Diccionarios planos clave → texto con {param}.
// t() busca en el idioma activo, luego en español y si no, devuelve la clave. Los parámetros se
// sustituyen en una sola pasada: un valor del correo con llaves no se vuelve a interpolar.
import ES from './es.js';
import EN from './en.js';

export const LANG_KEY = 'phishlens-lang';
export const LOCALE = Object.freeze({ es: 'es-ES', en: 'en-GB' });
const LANGS = new Set(['es', 'en']);

const toMap = (dict) => new Map(Object.entries(dict ?? {}));
let dicts = { es: toMap(ES), en: toMap(EN) };
let lang = 'es';
const listeners = new Set();

/** Solo para tests: cambia los diccionarios (null vuelve a los de verdad). */
export function _setDictionaries(next) {
  dicts = next ? { es: toMap(next.es), en: toMap(next.en) } : { es: toMap(ES), en: toMap(EN) };
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
