import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseEml } from '../../src/parser/eml.js';
import { parseDkimKeyRecord, verifyDkimSignature } from '../../src/auth/dkim.js';

const fixture = (name) => parseEml(readFileSync(new URL(`../fixtures/dkim/${name}.eml`, import.meta.url), 'utf8'));
const KEYS = JSON.parse(readFileSync(new URL('../fixtures/dkim/keys.json', import.meta.url), 'utf8'));
const RSA = KEYS['rsa2026._domainkey.banco-ficticio.test'];
const ED = KEYS['ed2026._domainkey.banco-ficticio.test'];

test('firma RSA válida (relaxed y simple)', async () => {
  for (const name of ['rsa-relaxed', 'rsa-simple', 'rsa-length']) {
    const r = await verifyDkimSignature(fixture(name), RSA);
    assert.deepEqual([r.ok, r.reason, r.domain, r.selector], [true, 'firma válida', 'banco-ficticio.test', 'rsa2026'], name);
  }
});

test('firma Ed25519 válida (RFC 8463)', async () => {
  const r = await verifyDkimSignature(fixture('ed25519-relaxed-simple'), ED);
  assert.equal(r.ok, true);
});

test('la clave de otro selector no vale', async () => {
  const r = await verifyDkimSignature(fixture('rsa-relaxed'), ED);
  assert.equal(r.ok, false);
});

test('una cabecera firmada alterada invalida la firma', async () => {
  const email = parseEml(readFileSync(new URL('../fixtures/dkim/rsa-relaxed.eml', import.meta.url), 'utf8').replace('Aviso', 'Alerta'));
  assert.deepEqual(await verifyDkimSignature(email, RSA), { ok: false, reason: 'firma no válida', domain: 'banco-ficticio.test', selector: 'rsa2026' });
});

test('cuerpo alterado', async () => {
  const r = await verifyDkimSignature(fixture('rsa-body-modified'), RSA);
  assert.deepEqual([r.ok, r.reason], [false, 'el cuerpo no coincide con bh=']);
});

test('clave revocada, mal formada y TXT partido en comillas', async () => {
  assert.equal((await verifyDkimSignature(fixture('rsa-relaxed'), 'v=DKIM1; k=rsa; p=')).reason, 'clave revocada');
  assert.equal((await verifyDkimSignature(fixture('rsa-relaxed'), 'esto no es una clave')).reason, 'clave mal formada');
  const p = RSA.split('p=')[1];
  const split = `"v=DKIM1; k=rsa; " "p=${p.slice(0, 100)}" "${p.slice(100)}"`;
  assert.equal((await verifyDkimSignature(fixture('rsa-relaxed'), split)).ok, true);
});

test('parseDkimKeyRecord', () => {
  assert.deepEqual(parseDkimKeyRecord('v=DKIM1; p='), { error: 'revoked' });
  assert.deepEqual(parseDkimKeyRecord('v=DKIM1; k=dsa; p=AAAA'), { error: 'unsupported' });
  assert.deepEqual(parseDkimKeyRecord('v=DKIM1; p=@@@'), { error: 'malformed' });
  assert.equal(parseDkimKeyRecord(ED).k, 'ed25519');
  assert.equal(parseDkimKeyRecord(ED).p.length, 32);
});

test('correo sin firma', async () => {
  assert.deepEqual(await verifyDkimSignature(parseEml('From: a@b.test\r\n\r\nhola'), RSA), { ok: false, reason: 'no hay firma DKIM', domain: '', selector: '' });
});

test('canonicalización simple con un .eml en LF', async () => {
  const lf = readFileSync(new URL('../fixtures/dkim/rsa-simple.eml', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const r = await verifyDkimSignature(parseEml(lf), RSA);
  assert.equal(r.reason, 'firma válida');
});

test('clave de otro tipo que la firma es un problema de clave, no una firma no válida', async () => {
  const r = await verifyDkimSignature(fixture('rsa-relaxed'), ED);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'algoritmo no compatible');
});
