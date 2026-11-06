// Textos llanos del modo sencillo (spec 2.3, §3): uno por regla, cortos, sin jerga y con punto final.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ruleIds } from '../../tools/gen-coverage.mjs';
import { PLAIN, plainFor } from '../../src/data/plain.js';
import { finding } from '../../src/core/finding.js';

const JARGON = ['SPF', 'DKIM', 'DMARC', 'MIME', 'ATT&CK', 'Received', 'header', 'punycode', 'boundary'];

test('cada regla tiene su texto llano', () => {
  const missing = ruleIds().filter((id) => !Object.hasOwn(PLAIN, id));
  assert.deepEqual(missing, []);
});

test('ningún texto pasa de 140 caracteres, lleva jerga o queda sin punto', () => {
  for (const [id, text] of Object.entries(PLAIN)) {
    const shown = text.replaceAll('{marca}', 'Banco Santander');
    assert.ok(shown.length <= 140, `${id}: ${shown.length} caracteres`);
    for (const word of JARGON) assert.ok(!text.toLowerCase().includes(word.toLowerCase()), `${id}: «${word}»`);
    assert.match(text, /\.$/, `${id}: sin punto final`);
  }
  assert.ok(Object.isFrozen(PLAIN));
});

test('plainFor: pone la marca, usa un genérico sin ella y cae en el título si la regla no existe', () => {
  assert.equal(plainFor('sender.brand-impersonation', 'Santander', 't'), 'Se hace pasar por Santander, pero lo envía otro.');
  assert.doesNotMatch(plainFor('sender.brand-impersonation', null, 't'), /\{marca\}/);
  assert.equal(plainFor('no.existe', null, 'Título'), 'Título');
  assert.equal(plainFor('constructor', null, 'Título'), 'Título');
});

test('finding() rellena plain', () => {
  const f = finding({ id: 'links.ip', detector: 'links', severity: 'high', title: 'Enlace a una dirección IP', detail: '' });
  assert.equal(f.plain, PLAIN['links.ip']);
  assert.equal(finding({ id: 'x.y', detector: 'links', severity: 'low', title: 'T', detail: '' }).plain, 'T');
});

test('los textos de SPF, DKIM y DMARC valen también para «none» o «neutral»: no dicen que el dominio rechace', () => {
  for (const id of ['auth.spf', 'auth.dkim', 'auth.dmarc']) {
    assert.doesNotMatch(PLAIN[id], /no da por bueno|rechaz|prohíbe|falla/i, id);
  }
});
