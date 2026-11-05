import { test } from 'node:test';
import assert from 'node:assert/strict';
import { highlight } from '../../src/ui/highlight.js';

test('marca frases sospechosas y URLs', () => {
  const parts = highlight('Hola. Su cuenta será suspendida hoy mismo. Entre en http://x.test/a ya.');
  const marked = parts.filter((p) => p.kind).map((p) => [p.kind, p.text]);
  assert.deepEqual(marked, [['phrase', 'será suspendida'], ['phrase', 'hoy mismo'], ['url', 'http://x.test/a']]);
  assert.equal(parts.map((p) => p.text).join(''), 'Hola. Su cuenta será suspendida hoy mismo. Entre en http://x.test/a ya.');
});
test('texto sin nada que marcar', () => {
  assert.deepEqual(highlight('Hola, ¿qué tal?'), [{ text: 'Hola, ¿qué tal?', kind: null }]);
});
test('rangos solapados no se duplican', () => {
  const parts = highlight('urgente urgente');
  assert.equal(parts.map((p) => p.text).join(''), 'urgente urgente');
});
test('limita textos enormes', () => {
  const parts = highlight('a'.repeat(100000));
  assert.ok(parts.map((p) => p.text).join('').length <= 20001);
});
