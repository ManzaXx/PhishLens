import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseUrl, extractUrls, registrableDomain } from '../../src/parser/url.js';

test('parseUrl obtiene el dominio registrable', () => {
  const u = parseUrl('https://www.paypal.com/x');
  assert.equal(u.hostname, 'www.paypal.com');
  assert.equal(u.registrableDomain, 'paypal.com');
  assert.equal(u.tld, 'com');
});

test('parseUrl detecta IPs', () => {
  assert.equal(parseUrl('http://192.168.1.10/login').isIp, true);
  assert.equal(parseUrl('https://example.com').isIp, false);
});

test('parseUrl detecta @ en la URL y usa el host real', () => {
  const u = parseUrl('http://paypal.com@evil.xyz/');
  assert.equal(u.hasAt, true);
  assert.equal(u.hostname, 'evil.xyz');
});

test('parseUrl detecta punycode', () => {
  assert.equal(parseUrl('https://xn--pypal-4ve.com').isPunycode, true);
});

test('parseUrl añade http:// a www.', () => {
  assert.equal(parseUrl('www.bbva.es').href, 'http://www.bbva.es/');
});

test('parseUrl devuelve null si no es una URL', () => {
  assert.equal(parseUrl('no es url'), null);
  assert.equal(parseUrl(''), null);
  assert.equal(parseUrl('mailto:a@b.com'), null);
});

test('registrableDomain con sufijos de segundo nivel', () => {
  assert.equal(registrableDomain('login.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(registrableDomain('a.b.example.es'), 'example.es');
  assert.equal(registrableDomain('localhost'), 'localhost');
});

test('extractUrls encuentra URLs y limpia la puntuación final', () => {
  assert.deepEqual(extractUrls('ve a https://a.com/x, y http://b.es.'), ['https://a.com/x', 'http://b.es']);
  assert.deepEqual(extractUrls('(www.c.com)'), ['www.c.com']);
});

test('extractUrls no se bloquea con miles de paréntesis', () => {
  const t = performance.now();
  assert.deepEqual(extractUrls(`http://a.b${')'.repeat(100000)}`), ['http://a.b']);
  assert.ok(performance.now() - t < 500);
});

test('extractUrls conserva paréntesis equilibrados', () => {
  assert.deepEqual(extractUrls('(ver https://es.wikipedia.org/wiki/Phishing_(fraude))'), ['https://es.wikipedia.org/wiki/Phishing_(fraude)']);
});

test('extractUrls no se bloquea con miles de puntos', () => {
  const t = performance.now();
  assert.equal(extractUrls(`http://a${'.'.repeat(200000)}x`).length, 1);
  assert.ok(performance.now() - t < 500);
});

test('unwrapUrl desenvuelve Safe Links y redirecciones de Google', async () => {
  const { unwrapUrl } = await import('../../src/parser/url.js');
  assert.equal(unwrapUrl('https://eur01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fevil.xyz%2Flogin&data=05'), 'http://evil.xyz/login');
  assert.equal(unwrapUrl('https://www.google.com/url?q=https://evil.xyz/a&sa=D'), 'https://evil.xyz/a');
  assert.equal(unwrapUrl('https://example.com/?url=http://x.test'), null);
  assert.equal(unwrapUrl('no url'), null);
});
