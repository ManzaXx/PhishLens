import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAuthResults } from '../../src/auth/authres.js';

test('cabecera de Gmail con comentarios y propiedades', () => {
  const r = parseAuthResults('mx.google.com; spf=pass (google.com: domain of a@b.test designates 1.2.3.4) smtp.mailfrom=a@b.test; dkim=pass header.i=@b.test header.s=s1 header.d=b.test; dmarc=pass (p=NONE) header.from=b.test');
  assert.equal(r.authservId, 'mx.google.com');
  assert.deepEqual(r.results.map((x) => [x.method, x.result]), [['spf', 'pass'], ['dkim', 'pass'], ['dmarc', 'pass']]);
  assert.equal(r.results[0].props['smtp.mailfrom'], 'a@b.test');
  assert.equal(r.results[1].props['header.d'], 'b.test');
  assert.equal(r.results[2].props['header.from'], 'b.test');
});

test('ignora la versión tras el authserv-id y mayúsculas', () => {
  const r = parseAuthResults('MX.Test 1; SPF=Pass smtp.mailfrom=x.test');
  assert.equal(r.authservId, 'mx.test');
  assert.deepEqual(r.results.map((x) => [x.method, x.result]), [['spf', 'pass']]);
});

test('"none" no da resultados', () => {
  assert.deepEqual(parseAuthResults('mx.test; none').results, []);
});

test('comentarios anidados y reason entre comillas', () => {
  const r = parseAuthResults('mx.test; dkim=fail (a (b; c) d) reason="bad; sig" header.d=x.test; spf=pass');
  assert.equal(r.results.length, 2);
  assert.equal(r.results[0].reason, 'bad; sig');
  assert.equal(r.results[0].props['header.d'], 'x.test');
});

test('como mucho 20 resultados', () => {
  const r = parseAuthResults(`mx.test; ${Array.from({ length: 30 }, () => 'spf=pass').join('; ')}`);
  assert.equal(r.results.length, 20);
});

test('100 KB de paréntesis sin cerrar terminan rápido', () => {
  const start = performance.now();
  parseAuthResults(`mx.test; spf=pass ${'('.repeat(100_000)}`);
  assert.ok(performance.now() - start < 50);
});

test('propiedades hostiles no contaminan prototipos', () => {
  const r = parseAuthResults('mx.test; spf=pass __proto__.polluted=yes constructor=x');
  assert.equal(({}).polluted, undefined);
  assert.equal(Object.getPrototypeOf(r.results[0].props), null);
});

test('entrada vacía o sin punto y coma', () => {
  assert.deepEqual(parseAuthResults(''), { authservId: '', results: [] });
  assert.deepEqual(parseAuthResults('mx.test').results, []);
});

test('Authentication-Results de Microsoft sin authserv-id', () => {
  const r = parseAuthResults('spf=pass (sender IP is 209.85.220.41) smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com');
  assert.equal(r.authservId, '');
  assert.deepEqual(r.results.map((x) => [x.method, x.result]), [['spf', 'pass'], ['dkim', 'pass']]);
  assert.equal(r.results[0].props['smtp.mailfrom'], 'gmail.com');
});
