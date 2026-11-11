// Módulo de idioma (spec 3.1): t() con parámetros y plurales, caída al español, idioma inicial y formatos.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { t, getLang, setLang, onLangChange, initialLang, fmtNumber, fmtDate, LANG_KEY, LOCALE, _setDictionaries } from '../../src/i18n/index.js';
import es from '../../src/i18n/es.js';
import en from '../../src/i18n/en.js';

afterEach(() => { setLang('es'); _setDictionaries(null); });

const DICTS = {
  es: { 'x.hola': 'Hola, {name}', 'x.solo-es': 'Solo en español', 'items.one': '{count} correo', 'items.other': '{count} correos', 'x.dos': '{name} y {count}' },
  en: { 'x.hola': 'Hello, {name}', 'items.one': '{count} email', 'items.other': '{count} emails', 'x.dos': '{name} and {count}' },
};

test('constantes', () => {
  assert.equal(LANG_KEY, 'phishlens-lang');
  assert.deepEqual(LOCALE, { es: 'es-ES', en: 'en-GB' });
  assert.equal(getLang(), 'es');
});

test('t: parámetros, caída al español y a la clave', () => {
  _setDictionaries(DICTS);
  assert.equal(t('x.hola', { name: 'Ana' }), 'Hola, Ana');
  setLang('en');
  assert.equal(t('x.hola', { name: 'Ana' }), 'Hello, Ana');
  assert.equal(t('x.solo-es'), 'Solo en español');
  assert.equal(t('no.existe'), 'no.existe');
  assert.equal(t('constructor'), 'constructor');
  assert.equal(t('__proto__'), '__proto__');
  assert.equal(t('x.hola'), 'Hello, {name}');
});

test('Review Focus 1: un valor con llaves no se vuelve a interpolar', () => {
  _setDictionaries(DICTS);
  assert.equal(t('x.dos', { name: '{count}', count: 3 }), '{count} y 3');
  assert.equal(t('x.hola', { name: '{name}' }), 'Hola, {name}');
});

test('t: plurales con Intl.PluralRules', () => {
  _setDictionaries(DICTS);
  assert.equal(t('items', { count: 1 }), '1 correo');
  assert.equal(t('items', { count: 2 }), '2 correos');
  assert.equal(t('items', { count: 0 }), '0 correos');
  setLang('en');
  assert.equal(t('items', { count: 1 }), '1 email');
  assert.equal(t('items', { count: 5 }), '5 emails');
});

test('setLang y onLangChange', () => {
  const seen = [];
  const off = onLangChange((l) => seen.push(l));
  setLang('fr');
  setLang('es');
  setLang('en');
  setLang('en');
  assert.deepEqual(seen, ['en']);
  off();
  setLang('es');
  assert.deepEqual(seen, ['en']);
  assert.equal(getLang(), 'es');
});

test('Review Focus 3: idioma inicial', () => {
  const cases = [
    [null, undefined, 'en'], [null, '', 'en'], [null, 'ES-es', 'es'], [null, 'es-419', 'es'], [null, 'pt-BR', 'en'],
    ['es', 'en-US', 'es'], ['en', 'es-ES', 'en'], ['xx', 'es', 'es'], [{}, 'en', 'en'], [undefined, 42, 'en'],
  ];
  for (const [stored, nav, want] of cases) assert.equal(initialLang(stored, nav), want, `${String(stored)} / ${String(nav)}`);
});

test('formatos', () => {
  assert.equal(fmtNumber(1234), '1.234');
  assert.equal(fmtNumber(123), '123');
  assert.equal(fmtNumber(1234567), '1.234.567');
  assert.equal(fmtDate('no-es-fecha'), '');
  assert.equal(fmtDate(new Date('2026-11-11T10:00:00Z'), { timeZone: 'UTC', dateStyle: 'short' }), '11/11/26');
  setLang('en');
  assert.equal(fmtNumber(1234), '1,234');
  assert.equal(fmtDate(new Date('2026-11-11T10:00:00Z'), { timeZone: 'UTC', dateStyle: 'short' }), '11/11/2026');
});

test('paridad de los diccionarios: mismas claves, mismos parámetros, sin vacíos', () => {
  const params = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
  assert.deepEqual(Object.keys(en).sort(), Object.keys(es).sort());
  for (const k of Object.keys(es)) {
    assert.ok(es[k].trim() && en[k].trim(), `vacío: ${k}`);
    assert.equal(params(en[k]), params(es[k]), `parámetros distintos en ${k}`);
  }
  assert.ok(Object.isFrozen(es) && Object.isFrozen(en));
});

test('src/i18n/ no importa de otras capas', () => {
  const dir = new URL('../../src/i18n/', import.meta.url);
  for (const name of readdirSync(dir)) {
    const code = readFileSync(new URL(name, dir), 'utf8');
    for (const m of code.matchAll(/from\s+['"]([^'"]+)['"]/g)) assert.match(m[1], /^\.\/[\w-]+\.js$/, `${name} → ${m[1]}`);
  }
});
