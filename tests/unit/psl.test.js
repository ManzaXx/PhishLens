// Dominio registrable con la Public Suffix List empaquetada (auditoría 3.1, P3 y P4).
// Dos subdominios de un servicio multiusuario (github.io, pages.dev…) son organizaciones distintas.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { domainToASCII } from 'node:url';
import { registrableDomain, organizationalDomain } from '../../src/parser/url.js';
import { dmarcAlignment } from '../../src/auth/dmarc.js';
import { PSL_META } from '../../src/data/psl.js';

test('batería oficial de publicsuffix.org (tests/test_psl.txt)', () => {
  const text = readFileSync(new URL('../fixtures/psl/test_psl.txt', import.meta.url), 'utf8');
  const cases = [...text.matchAll(/^checkPublicSuffix\((null|'[^']*'), (null|'[^']*')\);/gm)]
    .map(([, input, expected]) => [input === 'null' ? null : input.slice(1, -1), expected === 'null' ? null : expected.slice(1, -1)]);
  assert.ok(cases.length > 60, `solo ${cases.length} casos leídos`);
  // La batería escribe los IDN en Unicode; PhishLens compara siempre en punycode.
  const ascii = (d) => (d === null ? null : domainToASCII(d) || d.toLowerCase());
  const wrong = cases.filter(([input, expected]) => organizationalDomain(input) !== ascii(expected))
    .map(([input, expected]) => `${input} → ${organizationalDomain(input)} (esperado ${expected})`);
  assert.deepEqual(wrong, []);
});

test('servicios multiusuario: cada subdominio es su propia organización', () => {
  for (const [a, b] of [['attacker.github.io', 'legit.github.io'], ['foo.pages.dev', 'bar.pages.dev'], ['evil.herokuapp.com', 'shop.herokuapp.com'],
    ['a.netlify.app', 'b.netlify.app'], ['a.vercel.app', 'b.vercel.app'], ['x.blogspot.com', 'y.blogspot.com'], ['a.duckdns.org', 'b.duckdns.org']]) {
    assert.notEqual(registrableDomain(a), registrableDomain(b), `${a} / ${b}`);
  }
  assert.equal(registrableDomain('login.attacker.github.io'), 'attacker.github.io');
});

test('sufijos ICANN de varios niveles', () => {
  assert.equal(registrableDomain('login.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(registrableDomain('a.b.example.ne.jp'), 'example.ne.jp');
  assert.equal(registrableDomain('a.example.ltd.uk'), 'example.ltd.uk');
  assert.equal(registrableDomain('a.example.nom.es'), 'example.nom.es');
  assert.equal(registrableDomain('shop.example.com.es'), 'example.com.es');
  assert.equal(registrableDomain('mail.example.com.'), 'example.com');
  assert.equal(registrableDomain('WWW.Example.COM'), 'example.com');
});

test('IDN: Unicode y punycode son el mismo dominio', () => {
  assert.equal(registrableDomain('www.münchen.de'), 'xn--mnchen-3ya.de');
  assert.equal(registrableDomain('xn--mnchen-3ya.de'), 'xn--mnchen-3ya.de');
  assert.equal(dmarcAlignment({ fromDomain: 'münchen.de', dkim: [{ result: 'pass', domain: 'xn--mnchen-3ya.de' }] }).aligned, true);
});

test('sin dominio registrable se devuelve el propio nombre (nunca null) y las IP no cambian', () => {
  assert.equal(registrableDomain('localhost'), 'localhost');
  assert.equal(registrableDomain('github.io'), 'github.io');
  assert.equal(registrableDomain('co.uk'), 'co.uk');
  assert.equal(registrableDomain(''), '');
  assert.equal(registrableDomain('203.0.113.9'), '203.0.113.9');
  assert.equal(organizationalDomain('co.uk'), null);
});

test('DMARC: un sufijo público compartido no alinea', () => {
  assert.equal(dmarcAlignment({ fromDomain: 'attacker.github.io', dkim: [{ result: 'pass', domain: 'legit.github.io' }] }).aligned, false);
  assert.equal(dmarcAlignment({ fromDomain: 'foo.pages.dev', spf: { result: 'pass', domain: 'bar.pages.dev' } }).aligned, false);
  assert.equal(dmarcAlignment({ fromDomain: 'a.example.ne.jp', dkim: [{ result: 'pass', domain: 'evil.ne.jp' }] }).aligned, false);
  assert.equal(dmarcAlignment({ fromDomain: 'news.example.com', dkim: [{ result: 'pass', domain: 'mail.example.com' }] }).aligned, true);
});

test('entradas raras no lanzan y son rápidas', () => {
  for (const x of [null, undefined, '.', '..', 'a..b', '-.-', 'x'.repeat(5000), `${'a.'.repeat(2000)}com`, '[::1]', 'ex ample.com']) {
    assert.doesNotThrow(() => registrableDomain(x));
  }
});

test('la copia de la PSL dice de cuándo es y cuántas reglas tiene', (t) => {
  assert.match(PSL_META.date, /^\d{4}-\d{2}-\d{2}$/);
  assert.match(PSL_META.sha256, /^[0-9a-f]{64}$/);
  assert.ok(PSL_META.rules > 9000);
  const days = (Date.now() - Date.parse(PSL_META.date)) / 86400000;
  if (days > 180) t.diagnostic(`AVISO: la PSL tiene ${Math.round(days)} días; regenérala con node tools/gen-psl.mjs <fichero>`);
});
