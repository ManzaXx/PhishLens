import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertWithinBudget } from '../helpers/timing.js';
import { createHash } from 'node:crypto';
import { sha256 } from '../../src/lib/sha256.js';

// Vectores de NIST FIPS 180-4 (ejemplos de SHA-256).
test('sha256 de la cadena vacía', () => {
  assert.equal(sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('sha256("abc")', () => {
  assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('sha256 del mensaje de 448 bits', () => {
  assert.equal(sha256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
});

test('sha256 de un millón de "a" en menos de 200 ms', () => {
  const million = new Uint8Array(1_000_000).fill(0x61);
  assert.equal(assertWithinBudget(() => sha256(million), 200, 'sha256 de 1 MB'), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
});

test('sha256 en la frontera de bloque coincide con node:crypto', () => {
  for (const n of [55, 56, 63, 64, 65, 119, 128]) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37) & 0xff);
    assert.equal(sha256(bytes), createHash('sha256').update(bytes).digest('hex'), `longitud ${n}`);
  }
});

test('las cadenas se codifican en UTF-8', () => {
  assert.equal(sha256('contraseña'), createHash('sha256').update('contraseña', 'utf8').digest('hex'));
});
