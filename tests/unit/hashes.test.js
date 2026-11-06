// SHA-1 (RFC 3174 / FIPS 180-4) y MD5 (RFC 1321) propios, para los adjuntos.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { sha1 } from '../../src/lib/sha1.js';
import { md5 } from '../../src/lib/md5.js';
import { parseEml } from '../../src/parser/eml.js';
import { analyzeInput } from '../../src/core/engine.js';
import { iocsToText } from '../../src/intel/ioc.js';

const enc = (s) => new TextEncoder().encode(s);

test('sha1: vectores de FIPS 180-4', () => {
  assert.equal(sha1(enc('')), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
  assert.equal(sha1(enc('abc')), 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(sha1(enc('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')), '84983e441c3bd26ebaae4aa1f95129e5e54670f1');
  assert.equal(sha1(new Uint8Array(1_000_000).fill(0x61)), '34aa973cd4c4daa4f61eeb2bdbad27316534016f');
});

test('md5: vectores de RFC 1321 §A.5', () => {
  assert.equal(md5(enc('')), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.equal(md5(enc('a')), '0cc175b9c0f1b6a831c399e269772661');
  assert.equal(md5(enc('abc')), '900150983cd24fb0d6963f7d28e17f72');
  assert.equal(md5(enc('message digest')), 'f96b697d7cb7938d525a2f31aaf161d0');
  assert.equal(md5(enc('12345678901234567890123456789012345678901234567890123456789012345678901234567890')), '57edf4a22be3c955ac49da2e2107b67a');
});

test('sha1 y md5 en la frontera de bloque coinciden con node:crypto', () => {
  for (const n of [55, 56, 63, 64, 65, 119, 128, 1000]) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37) & 0xff);
    assert.equal(sha1(bytes), createHash('sha1').update(bytes).digest('hex'), `sha1 ${n}`);
    assert.equal(md5(bytes), createHash('md5').update(bytes).digest('hex'), `md5 ${n}`);
  }
});

const withAttachment = (b64) => [
  'From: a@b.test', 'Content-Type: multipart/mixed; boundary=Z', '', '--Z', 'Content-Type: text/plain', '', 'hola',
  '--Z', 'Content-Type: application/pdf; name="f.pdf"', 'Content-Transfer-Encoding: base64', '', b64, '--Z--',
].join('\n');

test('un adjunto trae SHA-256, SHA-1 y MD5; los IOCs y el texto copiado también', () => {
  const raw = readFileSync(new URL('../../samples/06-phishing-factura-adjunto.eml', import.meta.url), 'utf8');
  const [a] = parseEml(raw).attachments;
  assert.equal(a.sha256, createHash('sha256').update(a.bytes).digest('hex'));
  assert.equal(a.sha1, createHash('sha1').update(a.bytes).digest('hex'));
  assert.equal(a.md5, createHash('md5').update(a.bytes).digest('hex'));
  const report = analyzeInput({ kind: 'eml', value: raw });
  assert.deepEqual(report.iocs.sha1, [a.sha1]);
  assert.deepEqual(report.iocs.md5, [a.md5]);
  const text = iocsToText(report.iocs);
  assert.match(text, /# SHA-1\n[0-9a-f]{40}/);
  assert.match(text, /# MD5\n[0-9a-f]{32}/);
});

test('sin hashes si el adjunto está deformado o vacío', () => {
  const lossy = parseEml(withAttachment('JVBER!!!i0x')).attachments[0];
  assert.equal(lossy.sha1, null);
  assert.equal(lossy.md5, null);
  const empty = parseEml(withAttachment('')).attachments[0];
  assert.equal(empty.sha1, null);
  assert.equal(empty.md5, null);
});
