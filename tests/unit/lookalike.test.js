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
  // bbva-seguridad.com es combosquatting (marca + «seguridad»): grave desde el PR3.
  assert.deepEqual(out, ['lookalike.brand-in-domain:high', 'lookalike.typosquat:high']);
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

// ---- PR3: alfabetos mezclados y dominios enteros en otro alfabeto ----
import { detect as detectLookalike } from '../../src/detectors/lookalike.js';
import { parseEml as parse } from '../../src/parser/eml.js';

const host = (unicode) => new URL(`http://${unicode}`).hostname;
const linkMail = (...hosts) => parse(`From: a@b.test\nContent-Type: text/plain\n\n${hosts.map((h) => `http://${h}/login`).join('\n')}`);
const lookIds = (...hosts) => detectLookalike(linkMail(...hosts)).map((f) => `${f.id}:${f.severity}`);

test('dominio que mezcla latín y cirílico (pаypal con a cirílica)', () => {
  const found = detectLookalike(linkMail(host('pаypal.com')));
  const f = found.find((x) => x.id === 'lookalike.mixed-script-domain');
  assert.equal(f?.severity, 'high');
  assert.match(f.evidence, /pаypal\.com/);
  assert.match(f.evidence, /xn--/);
});

test('dominio entero en cirílico que dibuja una marca (аррӏе.com)', () => {
  assert.ok(lookIds('xn--80ak6aa92e.com').includes('lookalike.whole-script:high'));
});

test('dominios internacionales legítimos no son imitaciones', () => {
  assert.deepEqual(lookIds(host('españa.es'), host('münchen.de'), host('пример.рф')), []);
});

// ---- PR3: subdominios engañosos y combosquatting ----
test('el dominio oficial completo a la izquierda de otro dominio es un subdominio engañoso', () => {
  for (const h of ['paypal.com.cuenta-segura.test', 'login-paypal-com.test', 'paypal-com.evil.test', 'www.bancosantander.es.acceso.test']) {
    assert.deepEqual(lookIds(h), ['lookalike.deceptive-subdomain:high'], h);
  }
});

test('combosquatting: marca más palabra de acceso es grave; sin ella, media', () => {
  assert.deepEqual(lookIds('paypal-login.test'), ['lookalike.brand-in-domain:high']);
  assert.deepEqual(lookIds('secure.paypal-cuenta.test'), ['lookalike.brand-in-domain:high']);
  assert.deepEqual(lookIds('paypal-fans.test'), ['lookalike.brand-in-domain:medium']);
  const f = detectLookalike(linkMail('paypal-login.test')).find((x) => x.id === 'lookalike.brand-in-domain');
  assert.match(f.evidence, /login/);
});

test('los dominios oficiales y sus subdominios no dan nada', () => {
  assert.deepEqual(lookIds('paypal.com', 'www.paypal.com', 'login.paypal.com'), []);
});

// ---- PR3: marcas españolas ----
import { BRANDS } from '../../src/data/brands.js';

test('las marcas nuevas tienen fecha de comprobación y sus dominios oficiales no dan nada', () => {
  const nuevas = ['ING', 'Banco Sabadell', 'Bankinter', 'Unicaja', 'Openbank', 'Abanca', 'Bizum', 'DGT', 'Seguridad Social', 'SEUR', 'GLS', 'Movistar', 'Vodafone', 'Orange', 'Endesa', 'Iberdrola', 'DocuSign', 'Dropbox', 'WeTransfer', 'Binance', 'Coinbase', 'Steam'];
  for (const name of nuevas) {
    const brand = BRANDS.find((b) => b.name === name);
    assert.ok(brand, name);
    assert.match(brand.checked, /^\d{4}-\d{2}-\d{2}$/, name);
    for (const d of brand.domains) assert.deepEqual(lookIds(d, `www.${d}`), [], d);
  }
});

test('marcas genéricas solo como etiqueta completa: sin falsos positivos por parecido', () => {
  assert.deepEqual(lookIds('grange.test', 'bring.com', 'steamboat.test', 'kingston.test'), []);
  assert.deepEqual(lookIds('orange-factura.test'), ['lookalike.brand-in-domain:medium']);
  assert.deepEqual(lookIds('ing-acceso.test'), ['lookalike.brand-in-domain:high']);
});

test('la evidencia nombra las letras de otro alfabeto', () => {
  const f = detectLookalike(linkMail(host('pаypal.com'))).find((x) => x.id === 'lookalike.mixed-script-domain');
  assert.match(f.evidence, /U\+0430/);
});

test('homógrafos de marca con letras latinas raras u otros alfabetos (ɑpple, Cherokee, copto)', () => {
  for (const unicode of ['ɑpple.com', 'gᴏᴏgle.com']) {
    assert.ok(lookIds(host(unicode)).includes('lookalike.homoglyph:high'), unicode);
  }
  // Ꭺ (Cherokee) y ⲣ (copto) dibujan letras latinas sin ser cirílicas ni griegas.
  assert.ok(lookIds(host('Ꭺpple.com')).some((x) => x.startsWith('lookalike.')), 'cherokee');
  assert.ok(lookIds(host('aⲣple.com')).includes('lookalike.homoglyph:high'), 'coptic');
});

test('una etiqueta Unicode que no dibuja ninguna marca no es homógrafo', () => {
  assert.deepEqual(lookIds(host('café.es'), host('zürich.ch')), []);
});

test('marcas que son palabras corrientes no cuentan en subdominios ajenos (www.ing.unipi.it)', () => {
  assert.deepEqual(lookIds('www.ing.unipi.it', 'orange-business.com'), []);
});
