import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertWithinBudget } from '../helpers/timing.js';
import { domainToUnicode } from 'node:url';
import { decodeLabel, toUnicode } from '../../src/parser/punycode.js';

const cp = (...points) => String.fromCodePoint(...points);

test('vectores de RFC 3492 §7.1', () => {
  assert.equal(decodeLabel('egbpdaj6bu4bxfgehfvwxn'), cp(0x644, 0x64a, 0x647, 0x645, 0x627, 0x628, 0x62a, 0x643, 0x644, 0x645, 0x648, 0x634, 0x639, 0x631, 0x628, 0x64a, 0x61f));
  assert.equal(decodeLabel('ihqwcrb4cv8a8dqg056pqjye'), cp(0x4ed6, 0x4eec, 0x4e3a, 0x4ec0, 0x4e48, 0x4e0d, 0x8bf4, 0x4e2d, 0x6587));
  assert.equal(decodeLabel('3B-ww4c5e180e575a65lsy2b'), `3${cp(0x5e74)}B${cp(0x7d44, 0x91d1, 0x516b, 0x5148, 0x751f)}`);
  assert.equal(decodeLabel('-> $1.00 <--'), '-> $1.00 <-');
});

test('toUnicode de dominios homógrafos', () => {
  assert.equal(toUnicode('xn--80ak6aa92e.com'), 'аррӏе.com');
  assert.equal(toUnicode('XN--ESPAA-RTA.es'), 'españa.es');
  assert.equal(toUnicode('www.paypal.com'), 'www.paypal.com');
});

test('coincide con el decodificador de Node en dominios reales', () => {
  for (const unicode of ['münchen.de', 'españa.es', 'пример.рф', 'bücher.example', 'ελληνικά.gr', '例え.テスト', 'café.fr']) {
    const ascii = new URL(`http://${unicode}`).hostname;
    assert.equal(toUnicode(ascii), domainToUnicode(ascii), ascii);
  }
});

test('punycode mal formado devuelve null sin lanzar y en tiempo lineal', () => {
  for (const bad of ['', 'zz', '9999999999999999', `${'a'.repeat(62)}-${'9'.repeat(40)}`, '-', 'ab-ñ']) {
    assert.equal(decodeLabel(bad), null, bad);
  }
  assertWithinBudget(() => {
    assert.equal(decodeLabel('a'.repeat(1 << 20)), null);
    assert.equal(toUnicode(`xn--${'b'.repeat(1 << 20)}.com`), `xn--${'b'.repeat(1 << 20)}.com`);
  }, 50, 'punycode de 1 MB');
});

test('una etiqueta inválida se deja tal cual', () => {
  assert.equal(toUnicode('xn--.com'), 'xn--.com');
  assert.equal(toUnicode('xn--zz.test'), 'xn--zz.test');
});
