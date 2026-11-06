import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseEml } from '../../src/parser/eml.js';
import { detect } from '../../src/detectors/sender.js';

const mail = (h) => parseEml(`${h}\nSubject: x\n\nhola`);
const ids = (findings) => findings.map((f) => `${f.id}:${f.severity}`);

test('Reply-To de otro dominio es medio', () => {
  assert.deepEqual(ids(detect(mail('From: Tienda <info@tienda.test>\nReply-To: cobros@otro.test'))), ['sender.replyto-mismatch:medium']);
});

test('Return-Path de otro dominio registrable es leve', () => {
  assert.deepEqual(ids(detect(mail('From: Tienda <info@tienda.test>\nReturn-Path: <b@envios.test>'))), ['sender.returnpath-mismatch:low']);
  assert.deepEqual(detect(mail('From: Tienda <info@tienda.test>\nReturn-Path: <b@mail.tienda.test>')), []);
});

test('nombre de marca con dominio ajeno es grave', () => {
  assert.deepEqual(ids(detect(mail('From: "Banco Santander" <alertas@seguridad-clientes.test>'))), ['sender.brand-impersonation:high']);
});

test('marca escribiendo desde correo gratuito es grave', () => {
  assert.deepEqual(ids(detect(mail('From: PayPal Service <paypal.service@gmail.com>'))), ['sender.brand-impersonation:high']);
});

test('remitente legítimo no genera hallazgos', () => {
  assert.deepEqual(detect(mail('From: PayPal <service@paypal.com>\nReply-To: service@paypal.com')), []);
  assert.deepEqual(detect(mail('From: Amazon.es <pedidos@amazon.es>')), []);
});

test('mezcla de alfabetos en el nombre (homoglifos Unicode)', () => {
  // "Pаypal" con la "а" cirílica (U+0430)
  assert.deepEqual(ids(detect(mail('From: "Pаypal" <x@pay.test>'))), ['sender.mixed-script:high']);
});

test('caracteres invisibles en el nombre o el asunto', () => {
  const e = mail('From: "Pay\u200BPal Soporte" <x@pay.test>');
  assert.ok(detect(e).some((f) => f.id === 'sender.invisible-chars' && f.severity === 'medium'));
});

test('la evidencia marca los caracteres no latinos', () => {
  const [f] = detect(mail('From: "Pаypal" <x@pay.test>'));
  assert.equal(f.evidence, 'Pаypal → P[U+0430]ypal');
});

test('nombre visible con la dirección de otro dominio es grave', () => {
  const found = ids(detect(mail('From: "service@paypal.com" <x@evil.test>')));
  assert.ok(found.includes('sender.display-name-address:high'));
  assert.ok(ids(detect(mail('From: "PayPal <service@paypal.com>" <x@evil.test>'))).includes('sender.display-name-address:high'));
});

test('nombre visible con su propia dirección o una del mismo dominio no cuenta', () => {
  assert.deepEqual(ids(detect(mail('From: "ana@empresa.es" <ana@empresa.es>'))), []);
  assert.deepEqual(ids(detect(mail('From: "soporte@mail.empresa.es" <ana@empresa.es>'))), []);
});

test('Sender de otro dominio sin firma DKIM de ese dominio es leve', () => {
  assert.deepEqual(ids(detect(mail('From: Tienda <info@tienda.test>\nSender: envios@plataforma.test'))), ['sender.sender-mismatch:low']);
});

test('Sender de otro dominio con firma DKIM de ese dominio no cuenta', () => {
  assert.deepEqual(ids(detect(mail('DKIM-Signature: v=1; a=rsa-sha256; d=plataforma.test; s=s1; h=from; bh=x; b=y\nFrom: Tienda <info@tienda.test>\nSender: envios@plataforma.test'))), []);
  assert.deepEqual(ids(detect(mail('From: Tienda <info@tienda.test>\nSender: otro@tienda.test'))), []);
});

test('"Ing." o "Steam Cleaning" en el nombre no son ING ni Steam', () => {
  assert.deepEqual(ids(detect(mail('From: "Ing. Carlos López" <carlos@estudio.test>'))), []);
  assert.deepEqual(ids(detect(mail('From: "Steam Cleaning Co" <info@limpiezas.test>'))), []);
  assert.ok(ids(detect(mail('From: "ING Direct" <avisos@x.test>'))).some((x) => x.startsWith('sender.brand-impersonation')));
});

test('dirección camuflada en el nombre con letras cirílicas o de ancho completo', () => {
  for (const from of ['From: "seguridad@bbvа.es" <x@evil.test>', 'From: "soporte＠paypal.com" <x@evil.test>']) {
    assert.ok(ids(detect(mail(from))).includes('sender.display-name-address:high'), from);
  }
});

test('la suplantación de marca lleva el nombre de la marca', () => {
  const f = detect(mail('From: "PayPal" <x@pay.test>')).find((x) => x.id === 'sender.brand-impersonation');
  assert.equal(f.brand, 'PayPal');
});
