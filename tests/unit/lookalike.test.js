import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect, levenshtein, normalizeHomoglyphs, findLookalike } from '../../src/detectors/lookalike.js';

test('levenshtein', () => {
  assert.equal(levenshtein('paypal', 'paypal'), 0);
  assert.equal(levenshtein('paypa1', 'paypal'), 1);
  assert.equal(levenshtein('', 'abc'), 3);
});

test('normalizeHomoglyphs', () => {
  assert.equal(normalizeHomoglyphs('micr0s0ft'), 'microsoft');
  assert.equal(normalizeHomoglyphs('arnazon'), 'amazon');
  assert.equal(normalizeHomoglyphs('paypa1'), 'paypal');
});

test('findLookalike detecta typosquatting', () => {
  assert.equal(findLookalike('paypa1-login.xyz')?.brand.name, 'PayPal');
  assert.equal(findLookalike('micr0soft.com')?.brand.name, 'Microsoft');
  assert.equal(findLookalike('arnazon.com')?.brand.name, 'Amazon');
  assert.equal(findLookalike('netfllx-billing.com')?.brand.name, 'Netflix');
});

test('findLookalike no marca dominios oficiales ni ajenos', () => {
  assert.equal(findLookalike('paypal.com'), null);
  assert.equal(findLookalike('www.paypal.com'), null);
  assert.equal(findLookalike('google.com'), null);
  assert.equal(findLookalike('example.com'), null);
  assert.equal(findLookalike('dhl.de'), null);
  assert.equal(findLookalike('apple.com'), null);
  assert.equal(findLookalike('ample.com'), null);
});

test('marca exacta dentro de un dominio no oficial', () => {
  const r = findLookalike('bbva-seguridad.com');
  assert.equal(r.brand.name, 'BBVA');
  assert.equal(r.kind, 'brand-in-domain');
});

test('detect revisa remitente y enlaces sin duplicar', () => {
  const email = {
    from: { name: 'PayPal', address: 'a@paypa1.com', domain: 'paypa1.com' },
    links: [{ text: 'x', href: 'https://paypa1.com/a' }, { text: 'y', href: 'https://bbva-seguridad.com' }, { text: 'z', href: 'https://www.paypal.com' }],
  };
  const out = detect(email).map((f) => `${f.id}:${f.severity}`).sort();
  assert.deepEqual(out, ['lookalike.brand-in-domain:medium', 'lookalike.typosquat:high']);
});

test('dominios regionales oficiales no son sospechosos', () => {
  for (const d of ['outlook.es', 'hotmail.es', 'amazon.fr', 'amazon.com.mx', 'google.co.uk', 'dhl.fr', 'paypal.de', 'live.com']) {
    assert.equal(findLookalike(d), null, d);
  }
});

test('ccTLD solo vale para marcas que lo usan', () => {
  assert.equal(findLookalike('bbva-es.com')?.brand.name, 'BBVA');
  assert.equal(findLookalike('netflix.ru')?.kind, 'brand-in-domain');
});

test('palabras contenidas en una marca no son typosquatting', () => {
  assert.equal(findLookalike('cloud-mailer.test'), null);
  assert.equal(findLookalike('outlet-store.test'), null);
});
