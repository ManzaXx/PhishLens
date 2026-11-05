import { test } from 'node:test';
import assert from 'node:assert/strict';
import { skeleton, sameShape, scriptsOf } from '../../src/parser/skeleton.js';

test('skeleton lleva letras de otros alfabetos a su forma ASCII', () => {
  assert.equal(skeleton('ｐａｙｐａｌ'), 'paypal');
  assert.equal(skeleton('pаypаl'), 'paypal');
  assert.equal(skeleton('Ρаураl'), 'paypal');
});

test('sameShape compara también las ambigüedades ASCII (i/l/1, 0/o)', () => {
  assert.equal(sameShape('аррӏе', 'apple'), true);
  assert.equal(sameShape('paypa1', 'paypal'), true);
  assert.equal(sameShape('g00gle', 'google'), true);
  assert.equal(sameShape('пример', 'apple'), false);
});

test('scriptsOf distingue alfabetos e ignora cifras y guiones', () => {
  assert.deepEqual([...scriptsOf('pаypal')].sort(), ['Cyrillic', 'Latin']);
  assert.deepEqual([...scriptsOf('españa-2')], ['Latin']);
  assert.deepEqual([...scriptsOf('ελληνικά')], ['Greek']);
  assert.deepEqual([...scriptsOf('例え')], ['Other']);
});

test('skeleton es lineal con entradas enormes', () => {
  const t = performance.now();
  skeleton('а'.repeat(1 << 20));
  assert.ok(performance.now() - t < 500);
});
