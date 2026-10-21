import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../src/detectors/links.js';

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
  const t = performance.now();
  detect(withLinks({ text: 'a-'.repeat(200000), href: 'https://x.test/' }));
  assert.ok(performance.now() - t < 500, `tardó ${Math.round(performance.now() - t)} ms`);
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
