// Fuzzing del validador de reglas (spec 3.0, §7): con 2.000 ficheros mutados (semilla fija) nunca lanza,
// nunca tarda más de 50 ms con uno y nunca deja pasar una regla fuera de las listas cerradas.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateRules, OPERATORS, FIELD_NAMES } from '../../src/rules/validate.js';
import { rng, pick } from '../helpers/rng.js';

const ITER = Number(process.env.FUZZ_ITER ?? 2000) >= 2000 ? 2000 : Math.max(200, Number(process.env.FUZZ_ITER));
const SEED = Number(process.env.FUZZ_SEED ?? 20261110);
const MAX_MS = 50;

const rule = (i) => ({
  id: `regla-${i}`, title: `Regla ${i}`, severity: 'medium', category: 'sender', technique: 'T1566.002',
  when: { all: [
    { field: 'subject', op: 'contains', value: 'factura' },
    { any: [{ field: 'sender.domain', op: 'not-in', value: ['a.es', 'b.es'] }, { not: { field: 'link.url', op: 'count-gte', value: 2 } }] },
  ] },
});
const SEEDS = [{ phishlens: 'rules/1', rules: [rule(0)] }, { phishlens: 'rules/1', rules: Array.from({ length: 100 }, (_, i) => rule(i)) }];
const WEIRD = [null, true, 0, -1, 1.5, 1e308, '', '__proto__', 'constructor', 'prototype', 'toString', 'x'.repeat(5000), [], {}, [[[[[]]]]], { __proto__: null }];
const KEYS = ['__proto__', 'constructor', 'prototype', 'all', 'any', 'not', 'field', 'op', 'value', 'id', 'when', 'rules', 'phishlens', 'extra'];

function mutateValue(v, r, depth = 0) {
  if (depth > 6 || pick(r, 4) === 0) return WEIRD[pick(r, WEIRD.length)];
  if (Array.isArray(v)) {
    const out = v.map((x) => (pick(r, 5) === 0 ? mutateValue(x, r, depth + 1) : x));
    if (pick(r, 4) === 0) out.push(mutateValue(v[0], r, depth + 1));
    if (pick(r, 6) === 0) out.splice(pick(r, out.length + 1), 1);
    return out;
  }
  if (v && typeof v === 'object') {
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      if (pick(r, 12) === 0) continue;
      out[k] = pick(r, 4) === 0 ? mutateValue(x, r, depth + 1) : x;
    }
    if (pick(r, 6) === 0) Object.defineProperty(out, KEYS[pick(r, KEYS.length)], { value: mutateValue(v, r, depth + 1), enumerable: true, configurable: true, writable: true });
    return out;
  }
  return WEIRD[pick(r, WEIRD.length)];
}

function mutateText(text, r) {
  const at = pick(r, text.length + 1);
  switch (pick(r, 4)) {
    case 0: return text.slice(0, at) + text.slice(at + pick(r, 50));
    case 1: return text.slice(0, at) + String.fromCharCode(pick(r, 0x10000)) + text.slice(at);
    case 2: return text.slice(0, at) + '{"__proto__":{"polluted":1},"a":[' + text.slice(at);
    default: return text.replace('"op":"contains"', `"op":"${['matches', 'regex', 'CONTAINS', '__proto__'][pick(r, 4)]}"`);
  }
}

function checkAccepted(rules) {
  const ops = new Set(OPERATORS);
  const fields = new Set(FIELD_NAMES);
  const walk = (n) => {
    assert.ok(n && typeof n === 'object' && Object.getPrototypeOf(n) === Object.prototype);
    if (n.all || n.any) for (const c of n.all ?? n.any) walk(c);
    else if (n.not) walk(n.not);
    else {
      assert.ok(ops.has(n.op), n.op);
      assert.ok(fields.has(n.field), n.field);
    }
  };
  for (const r of rules) walk(r.when);
}

test(`fuzz del validador de reglas: ${ITER} ficheros mutados`, () => {
  const r = rng(SEED);
  let accepted = 0;
  for (let i = 0; i < ITER; i++) {
    const base = SEEDS[pick(r, SEEDS.length)];
    const text = pick(r, 2) ? JSON.stringify(mutateValue(base, r)) : mutateText(JSON.stringify(base), r);
    const t0 = performance.now();
    let out;
    assert.doesNotThrow(() => { out = validateRules(text); }, `iteración ${i}`);
    const ms = performance.now() - t0;
    assert.ok(ms < MAX_MS, `iteración ${i}: ${ms.toFixed(1)} ms`);
    if (out.ok) {
      accepted++;
      checkAccepted(out.rules);
    } else assert.ok(out.errors.length > 0 && out.errors.length <= 50);
  }
  assert.equal({}.polluted, undefined);
  assert.ok(accepted < ITER);
});
