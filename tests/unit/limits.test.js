import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LIMITS } from '../../src/lib/limits.js';
import { LIMITS as PARSER_LIMITS, parseEml } from '../../src/parser/eml.js';

test('límites centralizados con los valores de la 2.2, el lote de la 2.3 y las reglas de la 3.0', () => {
  assert.deepEqual({ ...LIMITS }, {
    depth: 20, parts: 500, links: 200, attachments: 100,
    attachmentBytes: 10 * 1024 * 1024, rawBytes: 25 * 1024 * 1024,
    inputBytes: 25 * 1024 * 1024, headers: 1000, headerBytes: 64 * 1024,
    batchFiles: 50, batchBytes: 100 * 1024 * 1024, ruleBodyChars: 256 * 1024,
  });
  assert.equal(PARSER_LIMITS, LIMITS);
});

const codes = (email) => email.parseNotes.map((n) => n.code);

test('más de 1.000 cabeceras: se leen 1.000 y se anota', () => {
  const head = Array.from({ length: 1200 }, (_, i) => `X-H${i}: v`).join('\r\n');
  const email = parseEml(`From: a@b.test\r\n${head}\r\n\r\nhola`);
  assert.equal(email.headerList.length, 1000);
  assert.ok(codes(email).includes('limit.headers'));
});

test('una cabecera de 200 KB se recorta a 64 KB y se anota', () => {
  const email = parseEml(`From: a@b.test\r\nSubject: ${'x'.repeat(200 * 1024)}\r\n\r\nhola`);
  assert.ok(email.headerList.find((h) => h.name === 'subject').value.length <= 64 * 1024);
  assert.ok(codes(email).includes('limit.header-bytes'));
});

test('una entrada de más de 25 MB se recorta, se anota y no lanza', () => {
  const email = parseEml(`From: a@b.test\r\nSubject: x\r\n\r\n${'a'.repeat(26 * 1024 * 1024)}`);
  assert.ok(codes(email).includes('limit.input-bytes'));
});

test('un adjunto base64 de 12 MB se decodifica solo hasta el límite', () => {
  const b64 = Buffer.alloc(12 * 1024 * 1024, 7).toString('base64').replace(/.{76}/g, '$&\r\n');
  const raw = `From: a@b.test\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="big.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64}\r\n--b--\r\n`;
  const start = performance.now();
  const email = parseEml(raw);
  const ms = performance.now() - start;
  const [a] = email.attachments;
  assert.equal(a.bytes.length, LIMITS.attachmentBytes);
  assert.equal(a.size, 12 * 1024 * 1024);
  assert.equal(a.truncated, true);
  assert.deepEqual([a.sha256, a.sha1, a.md5], [null, null, null]);
  assert.ok(ms < 1500, `${Math.round(ms)} ms`);
});

// ---------- Revisión final del PR5 ----------
import { analyzeInput } from '../../src/core/engine.js';
import { confidenceFor } from '../../src/core/confidence.js';

test('un adjunto base64 con 200 KB de «=» se analiza en tiempo lineal', () => {
  const raw = `From: a@b.test\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename="x.pdf"\r\nContent-Transfer-Encoding: base64\r\n\r\n${'='.repeat(200 * 1024)}A\r\n--b--\r\n`;
  const start = performance.now();
  parseEml(raw);
  const ms = performance.now() - start;
  assert.ok(ms < 500, `${Math.round(ms)} ms`);
});

test('1.000 cabeceras de relleno no esconden Content-Type ni From', () => {
  const filler = Array.from({ length: 1000 }, () => 'X-A: 1').join('\r\n');
  const raw = `${filler}\r\nFrom: PayPal <service@paypa1-seguridad.test>\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nPaga la factura\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="factura.pdf.exe"\r\n\r\nMZ\r\n--b--\r\n`;
  const report = analyzeInput({ kind: 'eml', value: raw });
  const found = report.findings.map((f) => f.id);
  assert.ok(found.includes('attachments.double-extension'), found.join(', '));
  assert.equal(report.email.from.address, 'service@paypa1-seguridad.test');
  assert.equal(report.confidence.level, 'low');
});

test('si no se ha leído todo el correo la confianza es baja', () => {
  for (const code of ['limit.headers', 'limit.input-bytes']) {
    const c = confidenceFor({ hasHeaders: true, auth: { spf: { state: 'verified' }, dkim: { state: 'verified' }, dmarc: { state: 'verified' } }, parseNotes: [{ code }], errors: [], categories: [] });
    assert.equal(c.level, 'low', code);
  }
});
