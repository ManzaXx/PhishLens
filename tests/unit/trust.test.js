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

// Hasta la 3.1 esto salía como «falsificado», pero es exactamente donde Postfix con OpenDKIM/OpenDMARC
// y Gmail escriben su propia cabecera (tests/unit/trust-layouts.test.js): no se puede distinguir.
// Sigue sin colar (no es de confianza ni da puntos a favor), pero tampoco acusa a un correo legítimo.
test('una cabecera justo debajo del único Received del receptor no cuela, pero queda sin confirmar', () => {
  const c = classifyAuthResults(mail(
    'Received: from vps.attacker.test ([203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Authentication-Results: mx.example.com; dmarc=pass header.from=b.test',
  ));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged, h.ambiguous]), [[false, false, true]]);
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

test('un Received inventado de la organización receptora no amplía la zona de confianza', () => {
  const c = classifyAuthResults(mail(
    'Received: from vps.attacker.test (vps.attacker.test [203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com',
    'Received: from out.paypal.com (out.paypal.com [64.4.250.33]) by mx2.example.com; Wed, 21 Oct 2026 07:03:01 +0000',
  ));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[false, true]]);
});

test('un HELO que finge ser del receptor sin rDNS no cuenta como salto interno', () => {
  const c = classifyAuthResults(mail(
    'Received: from mx2.example.com (unknown [203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Authentication-Results: mx.example.com; dmarc=pass header.from=b.test',
    'Received: from x.b.test by mx2.example.com; Wed, 21 Oct 2026 07:03:01 +0000',
  ));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[false, true]]);
});

test('los saltos internos legítimos del receptor siguen dentro de la zona de confianza', () => {
  const c = classifyAuthResults(mail(
    'Received: from mx-in.example.com (mx-in.example.com [10.0.0.5]) by store.example.com; Wed, 21 Oct 2026 07:03:06 +0000',
    'Authentication-Results: mx-in.example.com; dmarc=pass header.from=b.test',
    'Received: from out.b.test (out.b.test [198.51.100.7]) by mx-in.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
  ));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[true, false]]);
});

test('reenvío Gmail → Outlook: la cabecera de Google por debajo no es falsificación', () => {
  const c = classifyAuthResults(mail(
    'Authentication-Results: spf=pass (sender IP is 209.85.220.41) smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com',
    'Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by AM0EUR02FT010.mail.protection.outlook.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Received: by mx.google.com with SMTP id x; Wed, 21 Oct 2026 07:03:01 +0000',
    'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=origen.test; dkim=pass header.d=origen.test',
  ));
  assert.equal(c.headers[0].trusted, true);
  assert.equal(c.headers[1].forged, false);
});
