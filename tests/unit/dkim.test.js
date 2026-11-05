import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseEml } from '../../src/parser/eml.js';
import { parseDkimSignature, canonicalizeBody, canonicalizeHeader, checkDkimBodies } from '../../src/auth/dkim.js';

const fixture = (name) => readFileSync(new URL(`../fixtures/dkim/${name}.eml`, import.meta.url), 'utf8');
const sigValue = (raw) => parseEml(raw).headers.get('dkim-signature')[0];

test('parseDkimSignature lee las etiquetas de una firma real plegada', () => {
  const sig = parseDkimSignature(sigValue(fixture('rsa-relaxed')));
  assert.equal(sig.v, '1');
  assert.equal(sig.a, 'rsa-sha256');
  assert.deepEqual(sig.c, { header: 'relaxed', body: 'relaxed' });
  assert.equal(sig.d, 'banco-ficticio.test');
  assert.equal(sig.s, 'rsa2026');
  assert.deepEqual(sig.h, ['from', 'to', 'subject', 'date', 'message-id']);
  assert.equal(sig.l, null);
  assert.ok(!/\s/.test(sig.b) && sig.b.length > 300);
  assert.ok(!/\s/.test(sig.bh));
});

test('c= por defecto es simple/simple y "relaxed" solo es relaxed/simple', () => {
  assert.deepEqual(parseDkimSignature('v=1; a=rsa-sha256; d=x.test; s=s; h=from; bh=AA==; b=AA==').c, { header: 'simple', body: 'simple' });
  assert.deepEqual(parseDkimSignature('v=1; a=rsa-sha256; c=relaxed; d=x.test; s=s; h=from; bh=AA==; b=AA==').c, { header: 'relaxed', body: 'simple' });
});

test('una firma sin d=, s=, h=, b= o bh= es mal formada', () => {
  assert.equal(parseDkimSignature('v=1; a=rsa-sha256; s=s; h=from; bh=AA==; b=AA=='), null);
  assert.equal(parseDkimSignature(''), null);
});

test('canonicalización del cuerpo, ejemplo de RFC 6376 §3.4.5', () => {
  const body = ' C \r\nD \t E\r\n\r\n\r\n';
  assert.equal(canonicalizeBody(body, 'relaxed', null), ' C\r\nD E\r\n');
  assert.equal(canonicalizeBody(body, 'simple', null), ' C \r\nD \t E\r\n');
});

test('cuerpo vacío', () => {
  assert.equal(canonicalizeBody('', 'simple', null), '\r\n');
  assert.equal(canonicalizeBody('', 'relaxed', null), '');
});

test('LF y CRLF dan la misma canonicalización', () => {
  assert.equal(canonicalizeBody('a  b\nc\n\n', 'relaxed', null), canonicalizeBody('a  b\r\nc\r\n\r\n', 'relaxed', null));
  assert.equal(canonicalizeBody('a\nb\n', 'simple', null), 'a\r\nb\r\n');
});

test('canonicalización de cabeceras, ejemplo de RFC 6376 §3.4.5', () => {
  assert.equal(canonicalizeHeader('A: X', 'relaxed'), 'a:X');
  assert.equal(canonicalizeHeader('B : Y\t\r\n\tZ  ', 'relaxed'), 'b:Y Z');
  assert.equal(canonicalizeHeader('B : Y\t\r\n\tZ  ', 'simple'), 'B : Y\t\r\n\tZ  ');
});

for (const name of ['rsa-relaxed', 'rsa-simple', 'ed25519-relaxed-simple', 'rsa-length']) {
  test(`hash de cuerpo correcto: ${name}`, () => {
    const [r] = checkDkimBodies(parseEml(fixture(name)));
    assert.equal(r.bodyHashOk, true);
  });
}

test('el hash de cuerpo también cuadra si el navegador entrega LF', () => {
  const [r] = checkDkimBodies(parseEml(fixture('rsa-relaxed').replace(/\r\n/g, '\n')));
  assert.equal(r.bodyHashOk, true);
});

test('cuerpo alterado después de firmar', () => {
  const [r] = checkDkimBodies(parseEml(fixture('rsa-body-modified')));
  assert.equal(r.bodyHashOk, false);
});

test('l= mayor que el cuerpo no lanza y no cuadra', () => {
  const [r] = checkDkimBodies(parseEml(fixture('rsa-length').replace(/l=\d+/, 'l=99999')));
  assert.equal(r.bodyHashOk, false);
  assert.ok(r.issues.includes('l-tag'));
});

test('x= caducada, rsa-sha1 y algoritmo desconocido', () => {
  const sig = (extra, a = 'rsa-sha256') => parseEml(`DKIM-Signature: v=1; a=${a}; d=x.test; s=s; h=from; bh=AA==; b=AA==; t=1; ${extra}\r\nFrom: a@x.test\r\n\r\nhola\r\n`);
  assert.ok(checkDkimBodies(sig('x=2'), { now: Date.parse('2026-01-01') })[0].issues.includes('expired'));
  assert.ok(checkDkimBodies(sig('', 'rsa-sha1'))[0].issues.includes('rsa-sha1'));
  const unknown = checkDkimBodies(sig('', 'rot13'))[0];
  assert.ok(unknown.issues.includes('unknown-algorithm'));
  assert.equal(unknown.bodyHashOk, null);
});

test('firma mal formada', () => {
  const [r] = checkDkimBodies(parseEml('DKIM-Signature: basura\r\nFrom: a@x.test\r\n\r\nhola'));
  assert.equal(r.bodyHashOk, null);
  assert.deepEqual(r.issues, ['malformed']);
});

test('como mucho 10 firmas', () => {
  const sigs = Array.from({ length: 11 }, () => 'DKIM-Signature: v=1; a=rsa-sha256; d=x.test; s=s; h=from; bh=AA==; b=AA==').join('\r\n');
  assert.equal(checkDkimBodies(parseEml(`${sigs}\r\nFrom: a@x.test\r\n\r\nhola`)).length, 10);
});
