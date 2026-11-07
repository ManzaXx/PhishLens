// URLs sin visitarlas (spec 2.3, §5.3): cadena de saltos, IP ofuscadas, credenciales, entropía y puertos.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, shannon, MAX_HOPS } from '../../src/intel/url.js';

const NONE = { nestedRedirect: false, obfuscatedIp: false, credentials: false, highEntropy: false, openRedirect: false, nonStandardPort: false };
const b64 = (s) => Buffer.from(s).toString('base64');

test('Google /url: un salto y ningún rasgo', () => {
  const r = analyzeUrl('https://www.google.com/url?q=https://evil.test/x');
  assert.equal(r.final, 'https://evil.test/x');
  assert.deepEqual(r.hops.map((h) => h.via), [null, 'google']);
  assert.deepEqual(r.flags, NONE);
});

test('redirección anidada con codificación doble: tres saltos, anidada y abierta', () => {
  const r = analyzeUrl('https://r.test/go?url=https%3A%2F%2Fs.test%2Fr%3Fnext%3Dhttps%253A%252F%252Fevil.test%252Fpago');
  assert.equal(r.final, 'https://evil.test/pago');
  assert.equal(r.hops.length, 3);
  assert.deepEqual(r.hops.map((h) => h.via), [null, 'param:url', 'param:next']);
  assert.equal(r.flags.nestedRedirect, true);
  assert.equal(r.flags.openRedirect, true);
});

test('base64 en un parámetro', () => {
  const r = analyzeUrl(`https://a.test/?u=${b64('https://evil.test/')}`);
  assert.equal(r.final, 'https://evil.test/');
  assert.equal(r.hops[1].via, 'base64');
  const safe = analyzeUrl(`https://a.test/?u=${b64('https://evil.test/a?b=c').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')}`);
  assert.equal(safe.final, 'https://evil.test/a?b=c');
});

test('envoltorios conocidos no son redirección abierta', () => {
  const r = analyzeUrl('https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.test%2F&data=x');
  assert.equal(r.final, 'https://evil.test/');
  assert.equal(r.hops[1].via, 'safelinks');
  assert.equal(r.flags.openRedirect, false);
  assert.equal(analyzeUrl('https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.test%2F').hops[1].via, 'facebook');
  assert.equal(analyzeUrl('https://www.linkedin.com/redir/redirect?url=https%3A%2F%2Fevil.test%2F').hops[1].via, 'linkedin');
  // El mismo dominio no es redirección abierta.
  assert.equal(analyzeUrl('https://tienda.test/login?next=https://tienda.test/cuenta').flags.openRedirect, false);
});

test('Review Focus 2: 15 niveles, base64 enorme y % roto nunca rompen y paran a tiempo', () => {
  let deep = 'https://fin.test/';
  for (let i = 14; i >= 0; i--) deep = `https://h${i}.test/?url=${b64(deep)}`;
  const d = analyzeUrl(deep);
  assert.equal(MAX_HOPS, 10);
  assert.equal(d.hops.length, 11);
  assert.equal(d.truncated, true);
  assert.equal(d.cycle, false);
  assert.equal(analyzeUrl('https://www.google.com/url?q=https://evil.test/x').truncated, false);

  let t = Date.now();
  const huge = analyzeUrl(`https://a.test/?url=${'QUFB'.repeat(262144)}&next=%E0%A4%A`);
  assert.equal(huge.hops.length, 1);
  assert.doesNotThrow(() => analyzeUrl('https://a.test/?url=%E0%A4%A&u=%%%&redirect=https%3A%2F%2F'));
  assert.ok(Date.now() - t < 200, `tarda ${Date.now() - t} ms`);
  t = Date.now();
  for (let i = 0; i < 100; i++) analyzeUrl(deep);
  assert.ok((Date.now() - t) / 100 < 50);
});

test('Review Focus 5: IP ofuscadas en el texto original', () => {
  for (const u of ['http://3232235777/', 'http://0xC0A80001/', 'http://0300.0250.0.1/', 'http://[::ffff:c0a8:1]/', 'http://0x7f.1/']) {
    assert.equal(analyzeUrl(u).flags.obfuscatedIp, true, u);
  }
  assert.equal(analyzeUrl('http://192.168.0.1/').flags.obfuscatedIp, false);
  assert.equal(analyzeUrl('http://10.0.0.1:8080/').flags.obfuscatedIp, false);
});

test('credenciales y puertos', () => {
  assert.equal(analyzeUrl('https://u:clave@bank.test/').flags.credentials, true);
  assert.equal(analyzeUrl('https://paypal.com@evil.test/').flags.credentials, false);
  const p = analyzeUrl('https://x.test:8081/');
  assert.equal(p.flags.nonStandardPort, true);
  assert.equal(p.port, '8081');
  assert.equal(analyzeUrl('https://x.test:443/').flags.nonStandardPort, false);
  assert.equal(analyzeUrl('http://x.test:80/').flags.nonStandardPort, false);
});

test('entropía: hosts y rutas aleatorias, pero no el seguimiento', () => {
  assert.equal(shannon('aaaa'), 0);
  assert.equal(shannon('ab'), 1);
  assert.equal(shannon(''), 0);
  assert.equal(analyzeUrl('https://kq3v9zx7w2pl.test/').flags.highEntropy, true);
  assert.equal(analyzeUrl('https://correos.es/').flags.highEntropy, false);
  assert.equal(analyzeUrl('https://notificaciones-clientes.test/').flags.highEntropy, false);
  // El path aleatorio se mide (sale en la vista «URLs») pero no es regla: los enlaces de seguimiento lo tienen.
  const path = analyzeUrl('https://x.test/a/Zq8Lp3Vx9Rt2Mk7Wb4Nc6Hd1Yf5Gj0Qs');
  assert.ok(path.entropy.path >= 4.5);
  assert.equal(path.flags.highEntropy, false);
  assert.equal(analyzeUrl('https://email.mg.tienda.test/c/eJxNjkEOgyAQRc_iWsgAgxZX7ePqjhuDlQh9eCmdZQGb5bmEyn--Eb').flags.highEntropy, false);
  assert.equal(analyzeUrl('https://links.sendgrid.net/ls/click?upn=Zq8Lp3Vx9Rt2Mk7Wb4Nc6Hd1Yf5Gj0Qs/Zq8Lp3Vx9Rt2Mk7Wb4Nc6Hd1Yf5Gj0Qs').flags.highEntropy, false);
  const r = analyzeUrl('https://kq3v9zx7w2pl.test/');
  assert.ok(r.entropy.host > 3.5);
});

test('host Unicode y entradas que no son http(s)', () => {
  const r = analyzeUrl('https://xn--pypal-4ve.com/');
  assert.equal(r.hostname, 'xn--pypal-4ve.com');
  assert.notEqual(r.unicodeHost, r.hostname);
  assert.equal(analyzeUrl('javascript:alert(1)'), null);
  assert.equal(analyzeUrl(''), null);
  assert.equal(analyzeUrl(null), null);
  assert.equal(analyzeUrl('www.x.test').final, 'http://www.x.test/');
});
