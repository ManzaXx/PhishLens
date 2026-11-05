import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseEml } from '../../src/parser/eml.js';
import { detect } from '../../src/detectors/auth.js';
import { evaluateAuth } from '../../src/auth/index.js';
import { analyzeInput } from '../../src/core/engine.js';
import { techniqueFor } from '../../src/data/mitre.js';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const sampleText = (name) => read(`../../samples/${name}.eml`);
const sample = (name) => parseEml(sampleText(name));
const fixture = (name) => parseEml(read(`../fixtures/dkim/${name}.eml`));
const ids = (findings) => findings.map((f) => f.id);
const byId = (findings, id) => findings.find((f) => f.id === id);

test('muestra 03 declara dmarc=fail: auth.dmarc sin repetir auth.dmarc-unaligned', () => {
  const found = ids(detect(sample('03-phishing-banco')));
  assert.ok(found.includes('auth.dmarc'));
  assert.ok(!found.includes('auth.dmarc-unaligned'));
});

test('muestra 04 sin ningún pass alineado da auth.dmarc-unaligned', () => {
  const f = byId(detect(sample('04-phishing-correos')), 'auth.dmarc-unaligned');
  assert.ok(f);
  assert.equal(f.severity, 'medium');
  assert.equal(f.mitre.id, 'T1672');
});

test('Authentication-Results falsificada da auth.forged-results', () => {
  const email = parseEml([
    'Received: from vps.attacker.test ([203.0.113.9]) by mx.example.com; Wed, 21 Oct 2026 07:03:05 +0000',
    'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=b.test; dmarc=pass header.from=b.test',
    'From: a@b.test',
    '',
    'hola',
  ].join('\r\n'));
  const f = byId(detect(email), 'auth.forged-results');
  assert.ok(f);
  assert.equal(f.severity, 'high');
  assert.equal(f.reliability, 'high');
  assert.ok(!ids(detect(email)).includes('auth.missing'));
});

test('cuerpo alterado tras firmar da auth.dkim-body-modified verificado', () => {
  const f = byId(detect(fixture('rsa-body-modified')), 'auth.dkim-body-modified');
  assert.ok(f);
  assert.equal(f.severity, 'high');
  assert.equal(f.provenance, 'verified');
});

test('hash de cuerpo correcto da auth.dkim-body-verified a favor y sin puntos', () => {
  const f = byId(detect(fixture('rsa-relaxed')), 'auth.dkim-body-verified');
  assert.ok(f);
  assert.equal(f.points, 0);
  assert.equal(f.polarity, 'trust');
  assert.equal(f.mitre, null);
});

test('firma con l= da auth.dkim-weak', () => {
  const f = byId(detect(fixture('rsa-length')), 'auth.dkim-weak');
  assert.ok(f);
  assert.equal(f.severity, 'low');
  assert.equal(techniqueFor('auth.dkim-weak'), null);
});

test('evaluateAuth: muestra 01 tiene DMARC declarado por el receptor de confianza', () => {
  const a = evaluateAuth(sample('01-legitimo-newsletter'));
  assert.equal(a.dmarc.state, 'declared-trusted');
  assert.equal(a.dmarc.result, 'pass');
  assert.equal(a.dmarc.source, 'mx.example.com');
  assert.equal(a.spf.state, 'declared-trusted');
});

test('evaluateAuth: sin datos es absent; DKIM firmado sin clave es unverifiable', () => {
  assert.equal(evaluateAuth(parseEml('From: a@b.test\n\nhola')).dkim.state, 'absent');
  assert.equal(evaluateAuth(fixture('rsa-relaxed')).dkim.state, 'unverifiable');
});

test('evaluateAuth memoiza por email', () => {
  const email = sample('01-legitimo-newsletter');
  assert.equal(evaluateAuth(email), evaluateAuth(email));
});

test('cabecera sin zona de confianza baja la fiabilidad de auth.spf', () => {
  const trusted = byId(detect(sample('03-phishing-banco')), 'auth.spf');
  const untrusted = byId(detect(sample('04-phishing-correos')), 'auth.spf');
  assert.equal(trusted.reliability, 'medium');
  assert.equal(untrusted.reliability, 'low');
});

test('report.auth de la muestra 01 y sin cabeceras en bruto', () => {
  const report = analyzeInput({ kind: 'eml', value: sampleText('01-legitimo-newsletter') });
  assert.equal(report.auth.dmarc.state, 'declared-trusted');
  assert.ok(!JSON.stringify(report.auth).includes('"raw"'));
});

test('registro SPF pegado que rechaza la IP de origen da auth.spf-offline', () => {
  const report = analyzeInput({ kind: 'eml', value: sampleText('01-legitimo-newsletter'), spfRecord: 'v=spf1 -all' });
  const f = byId(report.findings, 'auth.spf-offline');
  assert.ok(f);
  assert.equal(f.severity, 'high');
  assert.equal(f.provenance, 'verified');
  assert.equal(report.auth.spf.state, 'verified');
  assert.equal(report.auth.spf.result, 'fail');
  assert.equal(report.auth.spf.source, 'PhishLens');
});

test('registro SPF con include es unverifiable y no inventa resultado', () => {
  const report = analyzeInput({ kind: 'eml', value: sampleText('01-legitimo-newsletter'), spfRecord: 'v=spf1 include:_spf.example.net -all' });
  assert.ok(!ids(report.findings).includes('auth.spf-offline'));
  assert.equal(report.auth.spf.state, 'declared-trusted');
  assert.match(report.auth.spf.detail, /include:_spf\.example\.net/);
});

test('firma DKIM verificada en local deja DKIM y DMARC como verified', () => {
  const report = analyzeInput({
    kind: 'eml',
    value: read('../fixtures/dkim/rsa-relaxed.eml'),
    dkim: { ok: true, reason: 'firma válida', domain: 'banco-ficticio.test', selector: 'rsa2026' },
  });
  assert.equal(report.auth.dkim.state, 'verified');
  assert.equal(report.auth.dkim.result, 'pass');
});

test('verifyDkimForInput verifica con la clave pegada y el informe lo refleja', async () => {
  const { verifyDkimForInput } = await import('../../src/core/engine.js');
  const value = read('../fixtures/dkim/rsa-relaxed.eml');
  const keys = JSON.parse(read('../fixtures/dkim/keys.json'));
  const dkim = await verifyDkimForInput({ kind: 'eml', value }, keys['rsa2026._domainkey.banco-ficticio.test']);
  assert.equal(dkim.ok, true);
  const report = analyzeInput({ kind: 'eml', value, dkim });
  assert.equal(report.auth.dkim.state, 'verified');
  assert.equal(report.auth.dmarc.state, 'verified');
});
