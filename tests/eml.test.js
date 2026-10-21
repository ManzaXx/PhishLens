import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseEml, parseAddress, htmlToText, emailFromUrl } from '../src/parser/eml.js';

const simple = [
  'From: "PayPal" <service@paypa1.com>',
  'To: victima@example.com',
  'Subject: Aviso',
  '  importante',
  'Reply-To: otro@evil.test',
  'Return-Path: <bounce@mailer.test>',
  '',
  'Hola, entra en https://paypa1.com/login ya.',
].join('\n');

test('une cabeceras plegadas', () => {
  const e = parseEml(simple);
  assert.equal(e.subject, 'Aviso importante');
  assert.equal(e.hasHeaders, true);
});

test('acepta saltos de línea CRLF', () => {
  const e = parseEml(simple.replace(/\n/g, '\r\n'));
  assert.equal(e.subject, 'Aviso importante');
  assert.match(e.text, /Hola/);
});

test('decodifica asuntos RFC 2047 en base64 y Q', () => {
  assert.equal(parseEml('Subject: =?UTF-8?B?w5psdGltbyBhdmlzbw==?=\n\nx').subject, 'Último aviso');
  assert.equal(parseEml('Subject: =?UTF-8?Q?Factura_pendiente?=\n\nx').subject, 'Factura pendiente');
  assert.equal(parseEml('Subject: =?utf-8?q?Hola?= =?utf-8?q?_mundo?=\n\nx').subject, 'Hola mundo');
});

test('parsea remitente, reply-to y return-path', () => {
  const e = parseEml(simple);
  assert.deepEqual(e.from, { name: 'PayPal', address: 'service@paypa1.com', domain: 'paypa1.com' });
  assert.equal(e.replyTo.domain, 'evil.test');
  assert.equal(e.returnPath, 'bounce@mailer.test');
  assert.deepEqual(e.headers.get('to'), ['victima@example.com']);
});

test('parseAddress acepta direcciones sin nombre', () => {
  assert.deepEqual(parseAddress('a@B.com'), { name: '', address: 'a@b.com', domain: 'b.com' });
  assert.equal(parseAddress(''), null);
});

test('extrae URLs del texto plano como enlaces', () => {
  const e = parseEml(simple);
  assert.deepEqual(e.links, [{ text: 'https://paypa1.com/login', href: 'https://paypa1.com/login' }]);
});

test('decodifica quoted-printable con saltos suaves', () => {
  const raw = [
    'Subject: qp',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'Caf=C3=A9 con le=',
    'che',
  ].join('\n');
  assert.equal(parseEml(raw).text.trim(), 'Café con leche');
});

test('multipart anidado con HTML y adjunto', () => {
  const html = '<p>Hola</p><a href="http://evil.xyz/login">https://paypal.com</a>';
  const raw = [
    'Subject: multi',
    'Content-Type: multipart/mixed; boundary="AAA"',
    '',
    '--AAA',
    'Content-Type: multipart/alternative; boundary=BBB',
    '',
    '--BBB',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from('Texto plano ñ').toString('base64'),
    '--BBB',
    'Content-Type: text/html; charset=utf-8',
    '',
    html,
    '--BBB--',
    '--AAA',
    'Content-Type: application/octet-stream; name="factura.pdf.exe"',
    'Content-Disposition: attachment;',
    ' filename="factura.pdf.exe"',
    'Content-Transfer-Encoding: base64',
    '',
    'TVqQAAMAAAAEAAAA',
    '--AAA--',
  ].join('\r\n');
  const e = parseEml(raw);
  assert.equal(e.text.trim(), 'Texto plano ñ');
  assert.match(e.html, /<a href/);
  assert.deepEqual(e.attachments, [{ filename: 'factura.pdf.exe', contentType: 'application/octet-stream' }]);
  assert.deepEqual(e.links, [{ text: 'https://paypal.com', href: 'http://evil.xyz/login' }]);
});

test('htmlToText quita etiquetas, scripts y entidades', () => {
  assert.equal(htmlToText('<style>p{}</style><p>Hola&nbsp;<b>mundo</b> &amp; m&aacute;s</p><script>x</script>'), 'Hola mundo & más');
});

test('texto sin cabeceras se trata como cuerpo', () => {
  const e = parseEml('Estimado cliente, verifique su cuenta en http://x.test');
  assert.equal(e.hasHeaders, false);
  assert.match(e.text, /Estimado cliente/);
  assert.equal(e.links.length, 1);
});

test('entrada vacía no lanza', () => {
  const e = parseEml('');
  assert.equal(e.hasHeaders, false);
  assert.equal(e.text, '');
  assert.deepEqual(e.links, []);
});

test('emailFromUrl crea un email mínimo con un enlace', () => {
  const e = emailFromUrl('http://192.168.0.1/login');
  assert.deepEqual(e.links, [{ text: 'http://192.168.0.1/login', href: 'http://192.168.0.1/login' }]);
  assert.equal(e.hasHeaders, false);
  assert.equal(e.from, null);
});

test('HTML malicioso no bloquea el parser (tiempo lineal)', () => {
  const inputs = [
    '<a href="x">'.repeat(100000),
    '<'.repeat(500000),
    '<script>'.repeat(100000),
    '<a href="x">y'.repeat(50000) + '</a>',
  ];
  for (const html of inputs) {
    const t = performance.now();
    parseEml(`From: a@b.com\nContent-Type: text/html\n\n${html}`);
    htmlToText(html);
    assert.ok(performance.now() - t < 1500, `tardó ${Math.round(performance.now() - t)} ms`);
  }
});
