import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze, analyzeInput, levelFor } from '../../src/core/engine.js';
import { parseEml } from '../../src/parser/eml.js';
import { finding } from '../../src/core/finding.js';

const fake = (name, severities) => ({
  name,
  detect: () => severities.map((s, i) => finding({ id: `${name}.${i}`, detector: name, severity: s, title: 't', detail: 'd' })),
});

test('levelFor y umbrales', () => {
  assert.equal(levelFor(0).level, 'safe');
  assert.equal(levelFor(24).level, 'safe');
  assert.equal(levelFor(25).level, 'suspicious');
  assert.equal(levelFor(59).level, 'suspicious');
  assert.equal(levelFor(60).level, 'phishing');
  assert.equal(levelFor(60).label, 'Probable phishing');
});

test('suma puntos, ordena por severidad y limita a 100', () => {
  const r = analyze(parseEml('From: a@b.com\n\nx'), [fake('a', ['low', 'high', 'high']), fake('b', ['high', 'medium'])]);
  assert.equal(r.score, 100);
  assert.equal(r.level, 'phishing');
  assert.deepEqual(r.findings.map((f) => f.severity), ['high', 'high', 'high', 'medium', 'low']);
});

test('un detector que falla no tumba el análisis', () => {
  const broken = { name: 'roto', detect: () => { throw new Error('boom'); } };
  const r = analyze(parseEml('From: a@b.com\n\nx'), [broken, fake('ok', ['medium'])]);
  assert.equal(r.score, 15);
  assert.deepEqual(r.errors, [{ detector: 'roto', message: 'boom' }]);
});

test('URL con IP y login es phishing', () => {
  const r = analyzeInput({ kind: 'url', value: 'http://192.168.0.1/paypal/login' });
  assert.equal(r.level, 'phishing');
});

test('URL legítima es segura', () => {
  assert.equal(analyzeInput({ kind: 'url', value: 'https://www.paypal.com/es/home' }).level, 'safe');
});

test('texto sin cabeceras avisa', () => {
  const r = analyzeInput({ kind: 'text', value: 'hola qué tal' });
  assert.ok(r.findings.some((f) => f.id === 'input.no-headers' && f.severity === 'info'));
  assert.equal(r.level, 'safe');
});

test('URL vacía o inválida avisa sin lanzar', () => {
  const r = analyzeInput({ kind: 'url', value: 'esto no es una url' });
  assert.ok(r.findings.some((f) => f.id === 'input.invalid-url'));
});

test('el informe incluye resumen y datos del email', () => {
  const r = analyzeInput({ kind: 'eml', value: 'From: "X" <x@y.com>\nSubject: Hola\n\nhttps://a.com' });
  assert.equal(r.email.subject, 'Hola');
  assert.equal(r.email.links.length, 1);
  assert.equal(typeof r.summary, 'string');
});

test('el resumen prioriza remitente y enlaces sobre autenticación', () => {
  const r = analyzeInput({ kind: 'eml', value: 'From: "PayPal" <a@pp-help.test>\nAuthentication-Results: x; spf=fail; dkim=fail; dmarc=fail\nSubject: x\n\nhola' });
  assert.match(r.summary, /^\d+ señales graves o medias, entre ellas «Se hace pasar por PayPal»/);
});

test('el informe no arrastra los bytes de los adjuntos (exportación JSON ligera)', () => {
  const raw = 'From: a@b.test\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Disposition: attachment; filename="a.bin"\r\nContent-Transfer-Encoding: base64\r\n\r\nYWJj\r\n--b--\r\n';
  const [a] = analyzeInput({ kind: 'eml', value: raw }).email.attachments;
  assert.equal(a.bytes, undefined);
  assert.equal(a.size, 3);
  assert.equal(a.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
