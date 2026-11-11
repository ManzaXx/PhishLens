// Disposiciones reales de cabeceras (auditoría 3.1, P1 y P2): dónde escribe cada servidor su
// Authentication-Results. Un correo legítimo nunca debe salir como «falsificado» solo porque su
// receptor escribe la cabecera debajo de su propio Received (Postfix con milters, Gmail).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseEml } from '../../src/parser/eml.js';
import { classifyAuthResults, receivingHop } from '../../src/auth/trust.js';
import { analyzeInput } from '../../src/core/engine.js';

const raw = (name) => readFileSync(new URL(`../fixtures/auth/${name}.eml`, import.meta.url), 'utf8');
const fixture = (name) => parseEml(raw(name));
const mail = (...headers) => parseEml(`${headers.join('\r\n')}\r\nFrom: a@b.test\r\n\r\nhola`);
const ids = (report) => report.findings.filter((f) => f.points > 0).map((f) => f.id);

test('Gmail completo: el receptor es mx.google.com, no la línea interna «by 2002:…»', () => {
  const { receiver } = receivingHop(fixture('gmail-completo'));
  assert.equal(receiver, 'mx.google.com');
});

test('Gmail completo: el ARC-Authentication-Results de Google por encima de la entrada es de confianza', () => {
  const c = classifyAuthResults(fixture('gmail-completo'));
  const arc = c.headers.find((h) => h.arc);
  assert.ok(arc, 'se lee el ARC-Authentication-Results');
  assert.deepEqual([arc.trusted, arc.forged], [true, false]);
  const below = c.headers.find((h) => !h.arc);
  assert.deepEqual([below.trusted, below.forged], [false, false]);
});

test('Gmail completo: DMARC pass de confianza y veredicto legítimo', () => {
  const r = analyzeInput({ kind: 'eml', value: raw('gmail-completo') });
  assert.equal(r.auth.dmarc.state, 'declared-trusted');
  assert.equal(r.auth.dmarc.result, 'pass');
  assert.ok(!ids(r).includes('auth.forged-results'), ids(r).join(' '));
  assert.equal(r.level, 'safe', `${r.score}: ${ids(r).join(' ')}`);
});

test('Gmail sin las líneas internas: la cabecera de debajo queda sin confirmar, no falsificada', () => {
  const c = classifyAuthResults(fixture('gmail-recortado'));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[false, false]]);
  assert.equal(c.headers[0].whyRef.code, 'auth.why.ambiguous');
  const r = analyzeInput({ kind: 'eml', value: raw('gmail-recortado') });
  assert.ok(!ids(r).includes('auth.forged-results'), ids(r).join(' '));
  assert.equal(r.level, 'safe', `${r.score}: ${ids(r).join(' ')}`);
});

test('Postfix + OpenDKIM/OpenDMARC: las cabeceras del milter, bajo el Received de Postfix, no son falsas', () => {
  const c = classifyAuthResults(fixture('postfix-opendkim'));
  assert.equal(c.receiver, 'mx.empresa.test');
  assert.deepEqual(c.headers.map((h) => h.forged), [false, false, false]);
  const r = analyzeInput({ kind: 'eml', value: raw('postfix-opendkim') });
  assert.ok(!ids(r).includes('auth.forged-results'), ids(r).join(' '));
  assert.equal(r.level, 'safe', `${r.score}: ${ids(r).join(' ')}`);
});

test('Microsoft 365: la cabecera sin authserv-id por encima sigue siendo de confianza', () => {
  const c = classifyAuthResults(fixture('m365'));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[true, false]]);
});

test('ataque: una cabecera con el nombre del receptor debajo de un salto ajeno sigue siendo falsa', () => {
  const c = classifyAuthResults(mail(
    'Received: from vps.attacker.test (vps.attacker.test [203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Received: from [10.0.0.2] by vps.attacker.test; Wed, 21 Oct 2026 07:03:01 +0000',
    'Authentication-Results: mx.example.com; dmarc=pass header.from=paypal.com',
  ));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[false, true]]);
});

test('ataque: si el receptor escribió su cabecera arriba, otra con su nombre debajo es falsa', () => {
  const c = classifyAuthResults(mail(
    'Authentication-Results: mx.example.com; dmarc=fail header.from=paypal.com',
    'Received: from vps.attacker.test (vps.attacker.test [203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Authentication-Results: mx.example.com; dmarc=pass header.from=paypal.com',
  ));
  assert.deepEqual(c.headers.map((h) => [h.trusted, h.forged]), [[true, false], [false, true]]);
});

test('ataque: un ARC-Authentication-Results por debajo de la entrada no da confianza', () => {
  const c = classifyAuthResults(mail(
    'Received: from vps.attacker.test (vps.attacker.test [203.0.113.9]) by mx.google.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'ARC-Authentication-Results: i=1; mx.google.com; dmarc=pass header.from=paypal.com',
  ));
  assert.equal(c.headers.some((h) => h.trusted), false);
});

test('ataque: ARC-Authentication-Results de otro dominio por encima no da confianza', () => {
  const c = classifyAuthResults(mail(
    'ARC-Authentication-Results: i=1; mx.attacker.test; dmarc=pass header.from=paypal.com',
    'Received: from vps.attacker.test (vps.attacker.test [203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
  ));
  assert.equal(c.headers.some((h) => h.trusted), false);
});

test('una línea «Received: by» sin nombre de host no se toma como receptor aunque sea la única', () => {
  const { receiver } = receivingHop(mail('Received: by 2002:a05:7300:5a13::1 with SMTP id k; Tue, 10 Nov 2026 10:00:03 -0800'));
  assert.equal(receiver, null);
});

test('parseHop: la IP entre paréntesis sin corchetes (formato de Exchange) también se lee', async () => {
  const { parseHop } = await import('../../src/parser/received.js');
  assert.equal(parseHop('from out.tienda.test (198.51.100.7) by AM0EUR02FT010.mail.protection.outlook.com (10.13.54.1) with Microsoft SMTP Server').ip, '198.51.100.7');
  assert.equal(parseHop('from AM0PR02MB1234.eurprd02.prod.outlook.com (2603:10a6:208:1::1) by DB9PR02MB5678.eurprd02.prod.outlook.com').ip, '2603:10a6:208:1::1');
  assert.equal(parseHop('from x.test (no es una ip) by y.test').ip, '');
});

test('ataque: un HELO de Outlook desde una IP pública cualquiera no alarga la zona de Microsoft', () => {
  const c = classifyAuthResults(mail(
    'Received: from AM0PR02MB1234.eurprd02.prod.outlook.com (203.0.113.9) by DB9PR02MB5678.eurprd02.prod.outlook.com with HTTPS; Tue, 10 Nov 2026 09:00:05 +0000',
    'Authentication-Results: spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com',
    'Received: from out.paypal.com (64.4.250.33) by AM0EUR02FT010.mail.protection.outlook.com with Microsoft SMTP Server; Tue, 10 Nov 2026 09:00:04 +0000',
  ));
  assert.equal(c.headers[0].trusted, false);
});

test('ataque: con el ARC de Gmail diciendo fail, una cabecera de Google debajo que dice pass es falsa', () => {
  const c = classifyAuthResults(mail(
    'ARC-Authentication-Results: i=1; mx.google.com; dmarc=fail header.from=paypal.com',
    'Received: from vps.attacker.test (vps.attacker.test [203.0.113.9]) by mx.google.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Authentication-Results: mx.google.com; dmarc=pass header.from=paypal.com',
  ));
  assert.deepEqual(c.headers.map((h) => [h.arc, h.trusted, h.forged]), [[true, true, false], [false, false, true]]);
});
