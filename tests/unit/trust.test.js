import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseEml } from '../../src/parser/eml.js';
import { classifyAuthResults } from '../../src/auth/trust.js';

const sample = (name) => parseEml(readFileSync(new URL(`../../samples/${name}.eml`, import.meta.url), 'utf8'));
const mail = (...headers) => parseEml(`${headers.join('\r\n')}\r\nFrom: a@b.test\r\n\r\nhola`);

test('la cabecera del receptor es de confianza (muestra 01)', () => {
  const c = classifyAuthResults(sample('01-legitimo-newsletter'));
  assert.equal(c.receiver, 'mx.example.com');
  assert.equal(c.headers.length, 1);
  assert.equal(c.headers[0].trusted, true);
  assert.equal(c.headers[0].forged, false);
});

test('una cabecera que imita al receptor por debajo de la frontera es falsa', () => {
  const c = classifyAuthResults(mail(
    'Authentication-Results: mx.example.com; spf=softfail smtp.mailfrom=attacker.test',
    'Received: from vps.attacker.test ([203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Received: from [10.0.0.2] by vps.attacker.test; Wed, 21 Oct 2026 07:03:01 +0000',
    'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=b.test; dmarc=pass header.from=b.test',
  ));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[true, false], [false, true]]);
});

test('una cabecera falsa justo debajo del único Received del receptor tampoco cuela', () => {
  const c = classifyAuthResults(mail(
    'Received: from vps.attacker.test ([203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Authentication-Results: mx.example.com; dmarc=pass header.from=b.test',
  ));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[false, true]]);
});

test('un reenvío legítimo no es falsificación', () => {
  const c = classifyAuthResults(mail(
    'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=origen.test',
    'Received: from relay.origen.test by mx.google.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Received: from app.origen.test by mx.origen.test; Wed, 21 Oct 2026 07:03:01 +0000',
    'Authentication-Results: mx.origen.test; spf=pass smtp.mailfrom=origen.test',
  ));
  assert.equal(c.receiver, 'mx.google.com');
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[true, false], [false, false]]);
});

test('un proveedor de confianza por encima de la frontera es fiable aunque no sea el receptor', () => {
  const c = classifyAuthResults(mail(
    'Authentication-Results: eur01.prod.outlook.com; dmarc=pass header.from=b.test',
    'Received: from x.b.test by mx.contoso.test; Wed, 21 Oct 2026 07:03:05 +0000',
  ));
  assert.equal(c.headers[0].trusted, true);
});

test('sin Received no hay zona de confianza ni falsificación', () => {
  const c = classifyAuthResults(mail('Authentication-Results: mx.example.com; dmarc=pass header.from=b.test'));
  assert.equal(c.receiver, null);
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged, h.why]), [[false, false, 'sin ruta Received']]);
});

test('un authserv-id con sufijo engañoso no pasa por Google', () => {
  const c = classifyAuthResults(mail(
    'Authentication-Results: mx.google.com.evil.test; dmarc=pass header.from=b.test',
    'Received: from x by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
  ));
  assert.equal(c.headers[0].trusted, false);
});
