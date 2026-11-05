import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defang, extractIocs, iocsToText } from '../../src/intel/ioc.js';
import { parseEml } from '../../src/parser/eml.js';

test('defang', () => {
  assert.equal(defang('http://evil.xyz/a.b'), 'hxxp://evil[.]xyz/a[.]b');
  assert.equal(defang('https://x.test'), 'hxxps://x[.]test');
  assert.equal(defang('a@b.com'), 'a[@]b[.]com');
  assert.equal(defang('203.0.113.9'), '203[.]0[.]113[.]9');
});

test('extractIocs reúne URLs, dominios, IPs, emails y adjuntos sin duplicados', () => {
  const e = parseEml([
    'Received: from x (x [203.0.113.9]) by mx.test; Tue, 20 Oct 2026 10:00:00 +0200',
    'Received: from y (y [10.0.0.1]) by x; Tue, 20 Oct 2026 10:00:00 +0200',
    'From: "A" <a@evil.test>',
    'Reply-To: b@other.test',
    'Content-Type: multipart/mixed; boundary=Z',
    '',
    '--Z',
    'Content-Type: text/plain',
    '',
    'Entra en http://evil.test/login y http://evil.test/login',
    '--Z',
    'Content-Type: application/octet-stream; name="f.pdf.exe"',
    '',
    'AA==',
    '--Z--',
  ].join('\n'));
  const iocs = extractIocs(e);
  assert.deepEqual(iocs.urls, ['http://evil.test/login']);
  assert.deepEqual(iocs.domains, ['evil.test', 'other.test']);
  assert.deepEqual(iocs.ips, ['203.0.113.9']);
  assert.deepEqual(iocs.emails, ['a@evil.test', 'b@other.test']);
  assert.deepEqual(iocs.attachments, ['f.pdf.exe']);
});

test('desenvuelve Safe Links en los IOCs', () => {
  const e = parseEml('From: a@b.test\n\nhttps://eur01.safelinks.protection.outlook.com/?url=http%3A%2F%2Fevil.xyz%2F&data=1');
  assert.ok(extractIocs(e).urls.includes('http://evil.xyz/'));
});

test('iocsToText genera un bloque listo para copiar', () => {
  const text = iocsToText({ urls: ['http://e.xyz/'], domains: ['e.xyz'], ips: [], emails: [], attachments: [] });
  assert.match(text, /# URLs\nhxxp:\/\/e\[\.\]xyz\//);
  assert.doesNotMatch(text, /# IPs/);
});

const attach = (name, b64) => `--b\r\nContent-Disposition: attachment; filename="${name}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64}\r\n`;

test('los SHA-256 de adjuntos son IOCs, sin repetir', () => {
  const raw = `From: a@b.test\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n${attach('a.exe', 'YWJj')}${attach('b.exe', 'YWJj')}--b--\r\n`;
  const iocs = extractIocs(parseEml(raw));
  assert.deepEqual(iocs.hashes, ['ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad']);
  assert.match(iocsToText(iocs), /# SHA-256\nba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad/);
});

test('un adjunto truncado no aporta hash', () => {
  const email = parseEml('From: a@b.test\r\n\r\nx');
  email.attachments = [{ filename: 'x', sha256: null }];
  assert.deepEqual(extractIocs(email).hashes, []);
});
