import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseEml } from '../../src/parser/eml.js';
import { detect } from '../../src/detectors/route.js';
import { isReservedIp } from '../../src/lib/ip.js';

const sample = (name) => parseEml(readFileSync(new URL(`../../samples/${name}.eml`, import.meta.url), 'utf8'));
const mail = (...received) => parseEml(`${received.map((r) => `Received: ${r}`).join('\r\n')}\r\nFrom: a@b.test\r\n\r\nhola`);
const ids = (email) => detect(email).map((f) => f.id);

test('isReservedIp', () => {
  for (const ip of ['10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '100.64.0.1', '127.0.0.1', '169.254.1.1', '::1', 'fd00::1', 'fe80::1']) assert.equal(isReservedIp(ip), true, ip);
  for (const ip of ['203.0.113.66', '172.32.0.1', '8.8.8.8', '2001:4860::1', 'no-ip', '']) assert.equal(isReservedIp(ip), false, ip);
});

test('IP privada en el salto que entra al receptor', () => {
  const email = mail('from x.attacker.test (x.attacker.test [192.168.1.20]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000');
  const f = detect(email).find((x) => x.id === 'route.private-ip-boundary');
  assert.ok(f);
  assert.equal(f.severity, 'medium');
});

test('IP privada entre servidores internos del receptor no cuenta', () => {
  const email = mail(
    'from mx-in.example.com (mx-in.example.com [10.0.0.5]) by store.example.com; Wed, 21 Oct 2026 07:03:06 +0000',
    'from out.b.test (out.b.test [198.51.100.7]) by mx-in.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
  );
  assert.deepEqual(ids(email), []);
});

test('salto anterior al previo en más de 5 minutos', () => {
  const email = mail(
    'from relay.b.test (relay.b.test [198.51.100.7]) by mx.example.com; Wed, 21 Oct 2026 07:00:00 +0000',
    'from app.b.test by relay.b.test; Wed, 21 Oct 2026 07:10:00 +0000',
  );
  assert.ok(ids(email).includes('route.time-travel'));
});

test('zonas horarias distintas y relojes desfasados menos de 5 min no viajan en el tiempo', () => {
  const email = mail(
    'from relay.b.test (relay.b.test [198.51.100.7]) by mx.example.com; Wed, 21 Oct 2026 16:03:00 +0200',
    'from app.b.test by relay.b.test; Wed, 21 Oct 2026 07:05:00 -0700',
  );
  assert.deepEqual(ids(email), []);
});

test('más de 24 h de entrega', () => {
  const email = mail(
    'from relay.b.test (relay.b.test [198.51.100.7]) by mx.example.com; Thu, 22 Oct 2026 08:00:00 +0000',
    'from app.b.test by relay.b.test; Wed, 21 Oct 2026 07:00:00 +0000',
  );
  const f = detect(email).find((x) => x.id === 'route.slow-delivery');
  assert.equal(f?.severity, 'low');
});

test('más de 25 saltos', () => {
  const hops = Array.from({ length: 26 }, (_, i) => `from h${i + 1}.b.test by h${i}.b.test; Wed, 21 Oct 2026 07:00:00 +0000`);
  assert.ok(ids(mail(...hops)).includes('route.too-many-hops'));
  assert.ok(!ids(mail(...hops.slice(0, 25))).includes('route.too-many-hops'));
});

test('Received ilegibles', () => {
  const f = detect(mail('???', '!!!')).find((x) => x.id === 'route.unparseable');
  assert.equal(f?.severity, 'info');
});

test('HELO que dice ser PayPal desde otro servidor', () => {
  const email = mail('from mail.paypal.com (vps.hosting.test [203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000');
  const f = detect(email).find((x) => x.id === 'route.helo-mismatch');
  assert.equal(f?.severity, 'high');
  assert.equal(f.mitre.id, 'T1684.002');
});

test('HELO de PayPal con rDNS de PayPal, o HELO no oficial, no da helo-mismatch', () => {
  assert.deepEqual(ids(mail('from mail.paypal.com (mx1.paypal.com [64.4.250.33]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000')), []);
  assert.deepEqual(ids(mail('from vps.hosting.test (vps.hosting.test [203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000')), []);
});

test('las muestras legítimas no dan ningún route.*', () => {
  assert.deepEqual(ids(sample('01-legitimo-newsletter')), []);
  assert.deepEqual(ids(sample('02-legitimo-pedido')), []);
});

test('sin cabeceras no opina', () => {
  assert.deepEqual(detect(parseEml('solo texto')), []);
});

test('hopWarnings: avisos en texto por salto para la interfaz', async () => {
  const { hopWarnings } = await import('../../src/detectors/route.js');
  const route = [
    { helo: 'app.b.test', by: 'relay.b.test', ip: '', time: Date.UTC(2026, 9, 21, 7, 10) },
    { helo: 'relay.b.test', by: 'mx.example.com', ip: '192.168.1.2', time: Date.UTC(2026, 9, 21, 7, 0), entry: true },
  ];
  assert.deepEqual(hopWarnings(route), [[], ['Entrada al servidor receptor', 'IP privada en la frontera', 'Hora anterior al salto previo']]);
});

test('salto interno de Office 365 (sin rDNS, mismo dominio en HELO y by) no da helo-mismatch', () => {
  const email = mail(
    'from SN6PR01MB1.namprd01.prod.outlook.com (2603:10b6:805:1::1) by BN6PR01MB2.namprd01.prod.outlook.com with HTTPS; Wed, 21 Oct 2026 07:03:06 +0000',
    'from mail-eopbgr.outbound.protection.outlook.com (mail-eopbgr.outbound.protection.outlook.com [40.107.1.1]) by SN6PR01MB1.namprd01.prod.outlook.com; Wed, 21 Oct 2026 07:03:05 +0000',
  );
  assert.deepEqual(ids(email), []);
});

test('Postfix + amavis en localhost por encima del salto externo no da IP privada', () => {
  const email = mail(
    'from localhost (localhost [127.0.0.1]) by mail.example.org (Postfix) with ESMTP id A; Wed, 21 Oct 2026 07:03:06 +0000',
    'from out.b.test (out.b.test [198.51.100.7]) by mail.example.org (Postfix) with ESMTPS id B; Wed, 21 Oct 2026 07:03:05 +0000',
  );
  assert.deepEqual(ids(email), []);
});

test('entrega LMTP interna con IP privada sin rDNS no da IP privada', () => {
  const email = mail(
    'from mail.example.org ([10.0.0.2]) by imap.example.org with LMTP; Wed, 21 Oct 2026 07:03:07 +0000',
    'from out.b.test (out.b.test [198.51.100.7]) by mail.example.org with ESMTPS; Wed, 21 Oct 2026 07:03:05 +0000',
  );
  assert.deepEqual(ids(email), []);
});
