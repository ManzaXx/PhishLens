import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertWithinBudget } from '../helpers/timing.js';
import { parseEml, emailFromUrl } from '../../src/parser/eml.js';
import { LIMITS } from '../../src/lib/limits.js';

const ABC_SHA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const withAttachment = (encoding, content) => [
  'From: a@b.test', 'Content-Type: multipart/mixed; boundary="b"', '',
  '--b', 'Content-Type: text/plain', '', 'hola',
  '--b', 'Content-Type: application/octet-stream', `Content-Transfer-Encoding: ${encoding}`,
  'Content-Disposition: attachment; filename="a.txt"', '', content,
  '--b--', '',
].join('\r\n');

const codes = (email) => email.parseNotes.map((n) => n.code);

test('headerList conserva el orden y el texto crudo con plegado', () => {
  const email = parseEml('Received: a\r\n\tb\r\nFrom: x@y.test\r\nReceived: c\r\n\r\nhola');
  assert.deepEqual(email.headerList.map((h) => h.name), ['received', 'from', 'received']);
  assert.equal(email.headerList[0].raw, 'Received: a\r\n\tb');
  assert.equal(email.headerList[0].value, 'a b');
  assert.deepEqual(email.headerList.map((h) => h.index), [0, 1, 2]);
});

test('rawBody es el cuerpo exacto', () => {
  assert.equal(parseEml('From: x@y.test\r\n\r\nhola').rawBody, 'hola');
});

test('adjunto base64: bytes, tamaño y sha256', () => {
  const [a] = parseEml(withAttachment('base64', 'YWJj')).attachments;
  assert.deepEqual([...a.bytes], [97, 98, 99]);
  assert.equal(a.size, 3);
  assert.equal(a.sha256, ABC_SHA);
  assert.equal(a.truncated, false);
});

test('adjunto quoted-printable y 7bit', () => {
  assert.equal(parseEml(withAttachment('quoted-printable', '=61bc')).attachments[0].sha256, ABC_SHA);
  assert.equal(parseEml(withAttachment('7bit', 'abc')).attachments[0].sha256, ABC_SHA);
});

test('base64 corrupto no lanza ni publica el hash del fichero vacío', () => {
  const email = parseEml(withAttachment('base64', '@@@'));
  const [a] = email.attachments;
  assert.equal(a.bytes.length, 0);
  assert.equal(a.sha256, null);
  assert.ok(codes(email).includes('mime.bad-base64'));
});

test('base64 truncado conserva el prefijo válido y no da hash', () => {
  const email = parseEml(withAttachment('base64', 'YWJjZ'));
  const [a] = email.attachments;
  assert.deepEqual([...a.bytes], [97, 98, 99]);
  assert.equal(a.sha256, null);
  assert.ok(codes(email).includes('mime.bad-base64'));
});

test('base64 válido sin relleno no se marca como corrupto', () => {
  const email = parseEml(withAttachment('base64', 'YWI'));
  assert.deepEqual([...email.attachments[0].bytes], [97, 98]);
  assert.ok(email.attachments[0].sha256);
  assert.ok(!codes(email).includes('mime.bad-base64'));
});

test('adjunto 8bit con caracteres no Latin-1 no da un hash falso', () => {
  const email = parseEml(withAttachment('8bit', '😀😀'));
  assert.equal(email.attachments[0].sha256, null);
  assert.ok(codes(email).includes('mime.lossy-attachment'));
});

test('un adjunto quoted-printable de 5 MB se decodifica en menos de 1 s', () => {
  const body = 'a'.repeat(75).concat('=\r\n').repeat(Math.ceil((5 * 1024 * 1024) / 78));
  const [a] = assertWithinBudget(() => parseEml(withAttachment('quoted-printable', body)).attachments, 1000, 'QP de 5 MB');
  assert.equal(a.size, 75 * Math.ceil((5 * 1024 * 1024) / 78));
});

test('adjunto mayor que el límite se trunca sin hash', () => {
  const old = LIMITS.attachmentBytes;
  LIMITS.attachmentBytes = 4;
  try {
    const email = parseEml(withAttachment('7bit', '0123456789'));
    const [a] = email.attachments;
    assert.equal(a.bytes.length, 4);
    assert.equal(a.size, 10);
    assert.equal(a.truncated, true);
    assert.equal(a.sha256, null);
    assert.ok(codes(email).includes('limit.attachment-bytes'));
  } finally {
    LIMITS.attachmentBytes = old;
  }
});

test('multipart sin cierre se lee y se anota', () => {
  const email = parseEml('From: a@b.test\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhola\r\n');
  assert.match(email.text, /hola/);
  assert.ok(codes(email).includes('mime.unterminated-multipart'));
});

test('el límite de partes se anota una sola vez', () => {
  const parts = Array.from({ length: 600 }, () => '--b\r\nContent-Type: text/plain\r\n\r\nx').join('\r\n');
  const email = parseEml(`From: a@b.test\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n${parts}\r\n--b--\r\n`);
  assert.equal(codes(email).filter((c) => c === 'limit.parts').length, 1);
});

test('entrada sin cabeceras y URL suelta tienen los campos nuevos vacíos', () => {
  for (const email of [parseEml('solo texto'), emailFromUrl('https://x.test')]) {
    assert.deepEqual(email.headerList, []);
    assert.equal(email.rawBody, '');
    assert.deepEqual(email.parseNotes, []);
  }
});
