// Validador de reglas propias (spec 3.0, §5.1 y §6): formato cerrado, topes y errores con regla, ruta y motivo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { validateRules, formatRuleError, RULES_LIMITS, HEADER_FIELDS, OPERATORS, FIELD_NAMES } from '../../src/rules/validate.js';

const EXAMPLE = {
  phishlens: 'rules/1',
  rules: [{
    id: 'mi-org.factura-falsa',
    title: 'Asunto de factura desde dominio nuevo',
    severity: 'medium',
    category: 'sender',
    technique: 'T1566.002',
    when: { all: [
      { field: 'subject', op: 'contains', value: 'Factura' },
      { field: 'sender.domain', op: 'not-in', value: ['mi-empresa.es', 'PROVEEDOR.es'] },
    ] },
  }],
};
const clone = (v) => JSON.parse(JSON.stringify(v));
const withRule = (patch) => {
  const f = clone(EXAMPLE);
  Object.assign(f.rules[0], patch);
  return JSON.stringify(f);
};
const withWhen = (when) => withRule({ when });
const cond = (field, op, value) => (value === undefined ? { field, op } : { field, op, value });
const errorsOf = (text) => {
  const r = validateRules(text);
  assert.equal(r.ok, false, 'debería rechazarse');
  return r.errors;
};
const firstError = (text) => formatRuleError(errorsOf(text)[0]);

test('acepta el ejemplo de §5.1 y devuelve la regla normalizada', () => {
  const r = validateRules(JSON.stringify(EXAMPLE));
  assert.equal(r.ok, true);
  assert.equal(r.rules.length, 1);
  const rule = r.rules[0];
  assert.deepEqual(Object.keys(rule), ['id', 'title', 'detail', 'severity', 'category', 'technique', 'when']);
  assert.equal(rule.detail, '');
  assert.equal(rule.technique, 'T1566.002');
  assert.deepEqual(rule.when, { all: [
    { field: 'subject', op: 'contains', value: 'factura' },
    { field: 'sender.domain', op: 'not-in', value: ['mi-empresa.es', 'proveedor.es'] },
  ] });
  assert.equal(Object.getPrototypeOf(rule.when), Object.prototype);
});

test('constantes: 20 cabeceras, 8 operadores y topes de la spec', () => {
  assert.equal(HEADER_FIELDS.length, 20);
  assert.deepEqual([...OPERATORS], ['equals', 'contains', 'starts-with', 'ends-with', 'in', 'not-in', 'exists', 'count-gte']);
  assert.deepEqual(RULES_LIMITS, { fileBytes: 200 * 1024, rules: 100, depth: 4, conditions: 20, values: 200 });
  assert.ok(FIELD_NAMES.includes('finding.id'));
  assert.ok(FIELD_NAMES.includes('body.text'));
});

test('rechaza el fichero entero si una regla falla, con regla, ruta y motivo', () => {
  const f = clone(EXAMPLE);
  f.rules.push({ ...clone(EXAMPLE.rules[0]), id: 'otra' }, { ...clone(EXAMPLE.rules[0]), id: 'tercera' });
  f.rules[2].when.all[1].op = 'matches';
  const r = validateRules(JSON.stringify(f));
  assert.equal(r.ok, false);
  assert.equal(formatRuleError(r.errors[0]), 'Regla 3, `when.all[1].op`: «matches» no es un operador admitido');
  assert.equal(formatRuleError({ rule: null, path: 'phishlens', reason: 'falta' }), 'Fichero, `phishlens`: falta');
});

test('cabecera y tamaño del fichero', () => {
  const cases = [
    ['no es json', /JSON/],
    ['[]', /objeto/],
    [JSON.stringify({ ...EXAMPLE, phishlens: 'rules/2' }), /rules\/1/],
    [JSON.stringify({ phishlens: 'rules/1', rules: {} }), /lista/],
    [JSON.stringify({ ...EXAMPLE, extra: 1 }), /extra/],
    [' '.repeat(RULES_LIMITS.fileBytes + 1), /200 KB/],
  ];
  for (const [text, re] of cases) assert.match(firstError(text), re, text.slice(0, 40));
  const many = clone(EXAMPLE);
  many.rules = Array.from({ length: 101 }, (_, i) => ({ ...clone(EXAMPLE.rules[0]), id: `regla-${i}` }));
  assert.match(firstError(JSON.stringify(many)), /100 reglas/);
});

test('campos de la regla', () => {
  const cases = [
    [{ id: 'Mayus' }, 'id'],
    [{ id: 'ab' }, 'id'],
    [{ id: 'a'.repeat(65) }, 'id'],
    [{ id: 'con espacio' }, 'id'],
    [{ title: 'x'.repeat(121) }, 'title'],
    [{ title: '' }, 'title'],
    [{ detail: 'x'.repeat(301) }, 'detail'],
    [{ severity: 'info' }, 'severity'],
    [{ category: 'otra' }, 'category'],
    [{ technique: 'T9999' }, 'technique'],
    [{ otra: 1 }, 'otra'],
  ];
  for (const [patch, path] of cases) {
    const [e] = errorsOf(withRule(patch));
    assert.equal(e.rule, 1);
    assert.equal(e.path, path, JSON.stringify(patch));
  }
  const dup = clone(EXAMPLE);
  dup.rules.push(clone(EXAMPLE.rules[0]));
  const [e] = errorsOf(JSON.stringify(dup));
  assert.deepEqual([e.rule, e.path], [2, 'id']);
  assert.match(e.reason, /repetid/);
});

test('condición: profundidad, número, operadores, campos y tipos de valor', () => {
  let deep = cond('subject', 'exists');
  for (let i = 0; i < 5; i++) deep = { all: [deep] };
  const cases = [
    [deep, /4 niveles/],
    [{ any: Array.from({ length: 21 }, () => cond('subject', 'exists')) }, /20 condiciones/],
    [cond('sender.domain', 'in', Array.from({ length: 201 }, (_, i) => `d${i}.es`)), /200 valores/],
    [cond('subject', 'matches', 'x'), /no es un operador admitido/],
    [cond('body.html', 'contains', 'x'), /no es un campo admitido/],
    [cond('header:x-otra', 'exists'), /no es un campo admitido/],
    [cond('subject', 'count-gte', 1), /lista/],
    [cond('link.url', 'count-gte', -1), /entero/],
    [cond('link.url', 'count-gte', 1.5), /entero/],
    [cond('sender.domain', 'in', 'x.es'), /lista/],
    [cond('subject', 'contains', 3), /texto/],
    [cond('subject', 'contains', ''), /texto/],
    [cond('subject', 'exists', 'x'), /value/],
    [{ all: [] }, /vacía/],
    [{ not: [cond('subject', 'exists')] }, /not/],
    [{ all: [cond('subject', 'exists')], any: [cond('subject', 'exists')] }, /una sola/],
    [{ field: 'subject', op: 'exists', otra: 1 }, /otra/],
  ];
  for (const [when, re] of cases) assert.match(firstError(withWhen(when)), re, JSON.stringify(when).slice(0, 60));
  assert.equal(validateRules(withWhen({ not: cond('header:x-mailer', 'exists') })).ok, true);
  assert.equal(validateRules(withWhen(cond('link.url', 'count-gte', 0))).ok, true);
});

test('Review Focus 1: __proto__, constructor y prototype como clave o como campo se rechazan y Object.prototype sigue limpio', () => {
  const texts = [
    '{"phishlens":"rules/1","rules":[],"__proto__":{"polluted":1}}',
    withRule({}).replace('"severity"', '"__proto__":{"polluted":1},"severity"'),
    withWhen({ all: [{ field: 'subject', op: 'exists', constructor: { prototype: { polluted: 1 } } }] }),
    withWhen(cond('__proto__', 'exists')),
    withWhen(cond('header:__proto__', 'exists')),
    withWhen(cond('constructor', 'exists')),
    withWhen(cond('subject', 'toString', 'x')),
  ];
  for (const text of texts) {
    const r = validateRules(text);
    assert.equal(r.ok, false, text.slice(0, 80));
  }
  assert.equal({}.polluted, undefined);
  assert.equal(Object.prototype.polluted, undefined);
});

test('acumula errores (50 como mucho) y nunca lanza con valores raros', () => {
  const f = clone(EXAMPLE);
  f.rules = Array.from({ length: 100 }, (_, i) => ({ id: `r-${i}`, title: '', severity: 'x', category: 'y', when: {} }));
  const errors = errorsOf(JSON.stringify(f));
  assert.equal(errors.length, 50);
  for (const v of [undefined, null, 1, {}, [], '""', 'null', '{"phishlens":"rules/1","rules":[null,1,"x",[]]}']) {
    assert.doesNotThrow(() => validateRules(v));
    assert.equal(validateRules(v).ok, false);
  }
});

test('no hay new RegExp ni RegExp( en src/rules/', () => {
  const dir = new URL('../../src/rules/', import.meta.url);
  for (const name of readdirSync(dir)) {
    const code = readFileSync(new URL(name, dir), 'utf8');
    assert.ok(!/RegExp\s*\(/.test(code), name);
  }
});

test('revisión final: listas anidadas 5.000 niveles en field, op o technique no hacen lanzar al validador', () => {
  // El texto se arma a mano: JSON.stringify de algo tan anidado ya desborda la pila en el propio test.
  const deep = `${'['.repeat(5000)}${']'.repeat(5000)}`;
  const base = withRule({ when: { field: 'subject', op: 'exists' }, technique: 'T1566.002' });
  for (const text of [
    base.replace('"field":"subject"', `"field":${deep}`),
    base.replace('"op":"exists"', `"op":${deep}`),
    base.replace('"technique":"T1566.002"', `"technique":${deep}`),
  ]) {
    assert.notEqual(text, base);
    let out;
    assert.doesNotThrow(() => { out = validateRules(text); });
    assert.equal(out.ok, false);
  }
});
