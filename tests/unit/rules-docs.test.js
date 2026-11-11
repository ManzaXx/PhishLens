// Documentación de las reglas propias (spec 3.0, §5.2): el ejemplo de docs/rules.md es el de samples/,
// pasa el validador, y el JSON Schema es JSON válido con los 8 operadores y los campos admitidos.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { validateRules, OPERATORS, FIELD_NAMES, RULES_LIMITS } from '../../src/rules/validate.js';

const read = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

test('el ejemplo de docs/rules.md es samples/rules/ejemplo.json y pasa validateRules', () => {
  const md = read('docs/rules.md');
  const block = md.match(/```json\n([\s\S]*?)\n```/);
  assert.ok(block, 'docs/rules.md lleva un bloque ```json');
  const sample = read('samples/rules/ejemplo.json');
  assert.deepEqual(JSON.parse(block[1]), JSON.parse(sample));
  const res = validateRules(block[1]);
  assert.equal(res.ok, true, JSON.stringify(res.errors));
  assert.equal(res.rules.length, 3);
});

test('docs/rules.md nombra los 8 operadores, los topes y todos los campos', () => {
  const md = read('docs/rules.md');
  for (const op of OPERATORS) assert.ok(md.includes(`\`${op}\``), op);
  for (const f of FIELD_NAMES.filter((x) => !x.startsWith('header:'))) assert.ok(md.includes(`\`${f}\``), f);
  for (const n of ['200 KB', `${RULES_LIMITS.rules} reglas`, `${RULES_LIMITS.depth} niveles`, `${RULES_LIMITS.conditions} condiciones`, `${RULES_LIMITS.values} valores`]) assert.ok(md.includes(n), n);
});

test('docs/rules.schema.json: JSON Schema 2020-12 con los 8 operadores y los campos', () => {
  const schema = JSON.parse(read('docs/rules.schema.json'));
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  const text = JSON.stringify(schema);
  for (const op of OPERATORS) assert.ok(text.includes(`"${op}"`), op);
  for (const f of FIELD_NAMES) assert.ok(text.includes(`"${f}"`), f);
});

test('ADR 0005 «Reglas declarativas sin regex» existe y está aceptada', () => {
  const p = new URL('../../docs/adr/0005-reglas-declarativas-sin-regex.md', import.meta.url);
  assert.ok(existsSync(p));
  assert.match(readFileSync(p, 'utf8'), /\*\*Estado:\*\* aceptada/);
});
