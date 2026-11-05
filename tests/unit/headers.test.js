import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseEml } from '../../src/parser/eml.js';
import { detect } from '../../src/detectors/headers.js';
import { parseReceived } from '../../src/parser/received.js';

const ids = (raw) => detect(parseEml(raw)).map((f) => `${f.id}:${f.severity}`).sort();
const base = 'From: a@tienda.test\nDate: Tue, 20 Oct 2026 10:00:00 +0200\nMessage-ID: <1@tienda.test>\nSubject: x\n';

test('email bien formado no genera hallazgos', () => {
  assert.deepEqual(ids(`${base}\nhola`), []);
});

test('Message-ID de otro dominio es leve', () => {
  assert.deepEqual(ids(base.replace('<1@tienda.test>', '<1@servidor-x.test>') + '\nhola'), ['headers.messageid-domain:low']);
});

test('faltan Date y Message-ID', () => {
  assert.deepEqual(ids('From: a@tienda.test\nSubject: x\n\nhola'), ['headers.missing-date:low', 'headers.missing-messageid:low']);
});

test('X-Mailer típico de kits de phishing', () => {
  assert.deepEqual(ids(`${base}X-Mailer: PHPMailer 6.8.0 (https://github.com/PHPMailer/PHPMailer)\n\nhola`), ['headers.mailer:medium']);
});

test('fecha en el futuro', () => {
  assert.deepEqual(ids(base.replace('2026', '2099') + '\nhola'), ['headers.future-date:low']);
});

test('sin cabeceras no opina', () => {
  assert.deepEqual(detect(parseEml('solo texto')), []);
});

test('parseReceived extrae los saltos en orden de llegada', () => {
  const e = parseEml([
    'Received: from mx2.example.com (mx2.example.com [203.0.113.9]) by mx.google.com; Tue, 20 Oct 2026 10:00:02 +0200',
    'Received: from [198.51.100.7] (unknown [198.51.100.7]) by mx2.example.com; Tue, 20 Oct 2026 10:00:01 +0200',
    'From: a@b.test', '', 'x',
  ].join('\n'));
  assert.deepEqual(parseReceived(e).map((h) => [h.from, h.by, h.ip]), [
    ['[198.51.100.7]', 'mx2.example.com', '198.51.100.7'],
    ['mx2.example.com', 'mx.google.com', '203.0.113.9'],
  ]);
});

test('parseReceived prefiere la IP real de conexión entre paréntesis', () => {
  const e = parseEml('Received: from [10.8.0.3] (unknown [198.51.100.23]) by vps.test; Wed, 21 Oct 2026 07:03:01 +0200\nFrom: a@b.test\n\nx');
  assert.equal(parseReceived(e)[0].ip, '198.51.100.23');
});

test('dos From es grave', () => {
  assert.deepEqual(ids(`${base}From: b@otra.test\n\nhola`), ['headers.duplicate-from:high']);
});

test('Subject, Date, To, Message-ID o Sender repetidos es medio, en un solo hallazgo', () => {
  const found = detect(parseEml(`${base}Subject: y\nTo: a@b.test\nTo: c@d.test\n\nhola`));
  assert.deepEqual(found.map((f) => `${f.id}:${f.severity}`), ['headers.duplicate:medium']);
  assert.match(found[0].evidence, /Subject/);
  assert.match(found[0].evidence, /To/);
});

test('Received y otras cabeceras repetibles no cuentan como duplicadas', () => {
  assert.deepEqual(ids(`Received: from a by b\nReceived: from c by a\nX-Tag: 1\nX-Tag: 2\n${base}\nhola`), []);
});
