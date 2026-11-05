import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { confidenceFor } from '../../src/core/confidence.js';
import { parseEml } from '../../src/parser/eml.js';
import { authReport } from '../../src/auth/index.js';

const state = (s) => ({ spf: { state: s }, dkim: { state: s }, dmarc: { state: s } });
const cats = (...scores) => scores.map((score, i) => ({ id: `c${i}`, score, max: 20 }));
const clean = { hasHeaders: true, auth: { spf: { state: 'verified' }, dkim: { state: 'declared-trusted' }, dmarc: { state: 'declared-trusted' } }, parseNotes: [], errors: [], categories: cats(0, 0) };

test('sin cabeceras ni autenticación la confianza es baja', () => {
  const c = confidenceFor({ ...clean, hasHeaders: false, auth: state('absent') });
  assert.equal(c.value, 0.3);
  assert.equal(c.level, 'low');
  assert.deepEqual(c.reasons, [
    'Sin cabeceras: solo se ha analizado el texto.',
    'La autenticación no se puede confirmar: no hay resultados de confianza.',
    'PhishLens no ha verificado nada por sí mismo.',
  ]);
});

test('muestra 01: cabeceras de confianza pero nada verificado, 0,90 alta', () => {
  const email = parseEml(readFileSync(new URL('../../samples/01-legitimo-newsletter.eml', import.meta.url), 'utf8'));
  const c = confidenceFor({ hasHeaders: email.hasHeaders, auth: authReport(email), parseNotes: email.parseNotes ?? [], errors: [], categories: cats(0) });
  assert.equal(c.value, 0.9);
  assert.equal(c.level, 'high');
});

test('la confianza no depende de la nota', () => {
  const a = confidenceFor({ ...clean, categories: cats(19.9, 0) });
  const b = confidenceFor({ ...clean, categories: cats(0, 2.5) });
  assert.deepEqual(a, b);
  assert.deepEqual(a.reasons, ['Solo una categoría aporta riesgo.']);
});

test('nunca baja de 0, ni con todas las carencias', () => {
  const c = confidenceFor({ hasHeaders: false, auth: state('unverifiable'), parseNotes: [{ code: 'x' }], errors: [{ detector: 'x' }], categories: cats(3) });
  assert.equal(c.value, 0);
  assert.equal(c.reasons.length, 6);
});

test('fronteras: 0,75 es alta y 0,65 media', () => {
  const high = confidenceFor({ ...clean, auth: state('declared-trusted'), parseNotes: [{ code: 'x' }] });
  assert.deepEqual([high.value, high.level], [0.75, 'high']);
  const medium = confidenceFor({ ...clean, auth: state('declared-trusted'), errors: [{}], categories: cats(3) });
  assert.deepEqual([medium.value, medium.level], [0.65, 'medium']);
});
