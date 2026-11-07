// Validador STIX 2.1 del proyecto (spec 2.3, §5.4): lo que rechaza y lo que acepta.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateBundle } from '../../tools/stix-validate.mjs';

const T = '2026-11-07T10:00:00.000Z';
const dom = { type: 'domain-name', spec_version: '2.1', id: 'domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7', value: 'example.com' };
const ind = {
  type: 'indicator', spec_version: '2.1', id: 'indicator--3f1a2b3c-4d5e-5f60-8a7b-0c1d2e3f4a5b', created: T, modified: T,
  name: 'Dominio', indicator_types: ['malicious-activity'], pattern: "[domain-name:value = 'example.com']", pattern_type: 'stix', valid_from: T,
};
const rel = {
  type: 'relationship', spec_version: '2.1', id: 'relationship--1a2b3c4d-5e6f-5a7b-8c9d-0e1f2a3b4c5d', created: T, modified: T,
  relationship_type: 'based-on', source_ref: ind.id, target_ref: dom.id,
};
const bundle = (...objects) => ({ type: 'bundle', id: 'bundle--0a1b2c3d-4e5f-5a6b-9c7d-8e9f0a1b2c3d', objects });
const errorsWith = (change) => {
  const b = structuredClone(bundle(dom, ind, rel));
  change(b);
  return validateBundle(b);
};

test('un bundle mínimo bien hecho no tiene errores', () => {
  assert.deepEqual(validateBundle(bundle(dom, ind, rel)), []);
});

test('rechaza cada fallo con su mensaje', () => {
  const cases = [
    [(b) => delete b.objects[1].spec_version, /spec_version/],
    [(b) => { b.objects[0].id = 'url--bedb4899-d24b-5401-bc86-8f6b4cc18ec7'; }, /id/],
    [(b) => { b.objects[0].id = 'domain-name--XYZ'; }, /id/],
    [(b) => { b.objects[1].created = '2026-11-07T10:00:00Z'; }, /created/],
    [(b) => { b.objects[2].target_ref = 'domain-name--00000000-0000-5000-8000-000000000000'; }, /no existe/],
    [(b) => { b.objects[1].pattern = "[domain-name:value = 'a'b']"; }, /pattern/],
    [(b) => { b.objects[1].pattern = "[mutex:name = 'x']"; }, /pattern/],
    [(b) => delete b.objects[2].source_ref, /source_ref/],
    [(b) => { b.type = 'paquete'; }, /bundle/],
    [(b) => { b.objects.push(structuredClone(b.objects[0])); }, /repetido/],
    [(b) => delete b.objects[0].value, /value/],
    [(b) => { b.objects[1].pattern_type = 'sigma'; }, /pattern_type/],
  ];
  for (const [change, re] of cases) {
    const errors = errorsWith(change);
    assert.ok(errors.some((e) => re.test(e)), `${change}: ${errors.join(' | ')}`);
  }
});

test('nunca lanza con basura', () => {
  for (const junk of [null, 1, 'x', [], {}, { type: 'bundle', id: 'bundle--x', objects: [null, 3, { type: '__proto__' }] }]) {
    assert.doesNotThrow(() => validateBundle(junk));
    assert.ok(validateBundle(junk).length > 0);
  }
});
