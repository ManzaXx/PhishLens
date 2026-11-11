import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertWithinBudget } from '../helpers/timing.js';
import { detect } from '../../src/detectors/links.js';

const withLinks = (...links) => ({ links: links.map((l) => (typeof l === 'string' ? { text: l, href: l } : l)) });
const ids = (findings) => findings.map((f) => `${f.id}:${f.severity}`).sort();

test('texto que muestra otro dominio que el destino', () => {
  assert.deepEqual(ids(detect(withLinks({ text: 'https://www.paypal.com', href: 'https://secure-pay.example/login' }))), ['links.mismatch:high']);
});

test('texto sin dominio no cuenta como mismatch', () => {
  assert.deepEqual(detect(withLinks({ text: 'Pulsa aquí', href: 'https://www.amazon.es/pedidos' })), []);
});

test('IP en vez de dominio', () => {
  assert.deepEqual(ids(detect(withLinks('https://192.168.10.5/cuenta'))), ['links.ip:high']);
});

test('acortador', () => {
  assert.deepEqual(ids(detect(withLinks('https://bit.ly/3abc'))), ['links.shortener:medium']);
});

test('arroba en la URL', () => {
  assert.deepEqual(ids(detect(withLinks('https://www.bbva.es@login.example/'))), ['links.at-sign:high']);
});

test('punycode', () => {
  assert.deepEqual(ids(detect(withLinks('https://xn--pypal-4ve.com/'))), ['links.punycode:high']);
});

test('TLD sospechoso', () => {
  assert.deepEqual(ids(detect(withLinks('https://ofertas.xyz/'))), ['links.tld:medium']);
});

test('login sin HTTPS', () => {
  assert.deepEqual(ids(detect(withLinks('http://clientes.example.com/login'))), ['links.insecure-login:medium']);
});

test('enlace normal no genera hallazgos', () => {
  assert.deepEqual(detect(withLinks('https://www.amazon.es/pedidos')), []);
});

test('no duplica hallazgos para el mismo enlace repetido', () => {
  assert.equal(detect(withLinks('https://bit.ly/x', 'https://bit.ly/x')).length, 1);
});

test('ignora enlaces que no son http(s)', () => {
  assert.deepEqual(detect(withLinks('javascript:alert(1)')), []);
});

test('marca en la ruta de un dominio ajeno', () => {
  assert.deepEqual(ids(detect(withLinks('https://files.example.net/paypal/verify'))), ['links.brand-in-path:medium']);
  assert.deepEqual(detect(withLinks('https://www.paypal.com/paypal/verify')), []);
});

test('texto de enlace enorme no bloquea el detector', () => {
  assertWithinBudget(() => detect(withLinks({ text: 'a-'.repeat(200000), href: 'https://x.test/' })), 500, 'texto de enlace enorme');
});

test('enlace de seguimiento de una plataforma de email es leve, no engaño', () => {
  assert.deepEqual(ids(detect(withLinks({ text: 'www.aerovelo.example', href: 'https://u1234.ct.sendgrid.net/ls/click?upn=abc' }))), ['links.tracking:low']);
  assert.deepEqual(ids(detect(withLinks({ text: 'tienda.example', href: 'https://tienda.us5.list-manage.com/track/click?u=1' }))), ['links.tracking:low']);
});

test('analiza el destino real de un enlace envuelto', () => {
  const out = detect(withLinks('https://eur01.safelinks.protection.outlook.com/?url=http%3A%2F%2F10.0.0.5%2Flogin&data=x'));
  assert.deepEqual(out.map((f) => f.id).sort(), ['links.insecure-login', 'links.ip']);
  assert.match(out[0].evidence, /10\.0\.0\.5/);
});

test('enlace que descarga un ejecutable o un comprimido', () => {
  assert.deepEqual(ids(detect(withLinks('https://files.example.net/factura.exe'))), ['links.download:high']);
  assert.deepEqual(ids(detect(withLinks('https://files.example.net/docs/fotos.zip?x=1'))), ['links.download:medium']);
});

test('punycode de un dominio internacional normal es leve y se muestra en Unicode', () => {
  const found = detect(withLinks('https://xn--espaa-rta.es/'));
  assert.deepEqual(ids(found), ['links.punycode:low']);
  assert.match(found[0].detail, /españa\.es/);
});

// ---------- URLs sin visitarlas (spec 2.3, §5.3) ----------
const b64 = (s) => Buffer.from(s).toString('base64');
const one = (href) => detect(withLinks(href));
const byId = (findings, id) => findings.find((f) => f.id === id);

test('links.nested-redirect: varios saltos, con la cadena como evidencia', () => {
  const href = `https://r.test/go?url=${encodeURIComponent(`https://s.test/r?next=${encodeURIComponent('https://destino.test/pago')}`)}`;
  const f = byId(one(href), 'links.nested-redirect');
  assert.equal(f.severity, 'medium');
  assert.equal(f.evidence, 'https://r.test/go?url=… → https://s.test/r?next=… → https://destino.test/pago');
  assert.equal(byId(one(href), 'links.open-redirect').severity, 'medium');
});

test('links.obfuscated-ip: una IP escrita como número', () => {
  const found = one('http://3232235777/login');
  assert.equal(byId(found, 'links.obfuscated-ip').severity, 'high');
  assert.ok(byId(found, 'links.obfuscated-ip').detail.includes('192.168.1.1'));
});

test('links.credentials-in-url sustituye a links.at-sign cuando hay contraseña', () => {
  assert.deepEqual(ids(one('https://u:p@paypal.com@x.test/')), ['links.credentials-in-url:high']);
  assert.deepEqual(ids(one('https://www.bbva.es@login.example/')), ['links.at-sign:high']);
});

test('links.high-entropy y links.non-standard-port', () => {
  assert.equal(byId(one('https://kq3v9zx7w2pl.test/entrega'), 'links.high-entropy').severity, 'low');
  assert.equal(byId(one('https://tienda.test:8443/'), 'links.non-standard-port').severity, 'low');
  assert.ok(byId(one('https://tienda.test:8443/'), 'links.non-standard-port').detail.includes('8443'));
});

test('el resto de comprobaciones mira el destino final', () => {
  assert.deepEqual(ids(one(`https://a.test/?u=${b64('https://bit.ly/3abc')}`)).filter((i) => i.startsWith('links.shortener')), ['links.shortener:medium']);
});

test('Review Focus 1: enlaces de seguimiento de una newsletter no disparan ninguna regla nueva', () => {
  const found = detect(withLinks(
    'https://u123.ct.sendgrid.net/ls/click?upn=Zq8Lp3Vx9Rt2Mk7Wb4Nc6Hd1Yf5Gj0QsZq8Lp3Vx9Rt2Mk7Wb4Nc6Hd1Yf5Gj0Qs',
    'https://tienda.us1.list-manage.com/track/click?u=4f2a9c&id=77b1e3&e=9a0f',
    `https://mandrillapp.com/track/click/31/tienda.test?p=${b64('{"u":"x"}')}&u=${encodeURIComponent('https://tienda.test/ofertas')}`,
    'https://email.mg.tienda.test/c/eJxNjkEOgyAQRc_iWsgAgxZX7ePqjhuDlQh9eCmdZQGb5bmEyn--Eb',
    'https://tienda.test/producto?utm_source=newsletter&utm_campaign=otono',
  ));
  const fresh = ['nested-redirect', 'obfuscated-ip', 'credentials-in-url', 'high-entropy', 'open-redirect', 'non-standard-port'].map((x) => `links.${x}`);
  assert.deepEqual(found.map((f) => f.id).filter((id) => fresh.includes(id)), []);
});
