import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseEml } from '../src/parser/eml.js';
import { detect } from '../src/detectors/sender.js';

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
  const e = mail('From: "Pay​Pal Soporte" <x@pay.test>');
  assert.ok(detect(e).some((f) => f.id === 'sender.invisible-chars' && f.severity === 'medium'));
});

test('la evidencia marca los caracteres no latinos', () => {
  const [f] = detect(mail('From: "Pаypal" <x@pay.test>'));
  assert.equal(f.evidence, 'Pаypal → P[U+0430]ypal');
});
