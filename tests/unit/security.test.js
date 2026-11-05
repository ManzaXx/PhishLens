// Pruebas de seguridad: entradas hostiles que intentan romper, bloquear o engañar a PhishLens.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseEml, parseAddress } from '../../src/parser/eml.js';
import { decodeEntities, htmlToText } from '../../src/parser/html.js';
import { analyzeInput } from '../../src/core/engine.js';
import { reveal } from '../../src/lib/text.js';
import { detect as detectHtml } from '../../src/detectors/html.js';

const fast = (fn, ms = 1000) => {
  const t = performance.now();
  fn();
  const elapsed = performance.now() - t;
  assert.ok(elapsed < ms, `tardó ${Math.round(elapsed)} ms`);
};

// ---------- Prototype pollution y claves heredadas ----------

test('entidades HTML con nombres de propiedades heredadas no se sustituyen', () => {
  assert.equal(decodeEntities('&constructor; &toString; &__proto__;'), '&constructor; &toString; &__proto__;');
});

test('resultados de autenticación con nombres heredados no rompen el detector', () => {
  const r = analyzeInput({ kind: 'eml', value: 'From: a@b.test\nAuthentication-Results: x; spf=constructor; dkim=__proto__; dmarc=tostring\n\nx' });
  assert.deepEqual(r.errors, []);
});

test('parámetros MIME con __proto__ no contaminan prototipos', () => {
  parseEml('From: a@b.test\nContent-Type: text/plain; __proto__=x; constructor=y; polluted=1\n\nx');
  assert.equal({}.polluted, undefined);
  assert.equal(Object.prototype.x, undefined);
});

// ---------- Denegación de servicio (ReDoS y tamaño) ----------

test('remitente con miles de "<" no bloquea parseAddress', () => {
  fast(() => parseAddress('<'.repeat(200000)));
  fast(() => parseAddress(`${'"'.repeat(100000)}<a@b.c`));
  assert.deepEqual(parseAddress('"Ana" <ana@x.test>'), { name: 'Ana', address: 'ana@x.test', domain: 'x.test' });
});

test('nombre de remitente enorme no bloquea la detección de alfabetos mezclados', () => {
  fast(() => analyzeInput({ kind: 'eml', value: `From: "${'a'.repeat(300000)}" <a@b.test>\n\nx` }));
});

test('cabeceras Received enormes y numerosas no bloquean', () => {
  const received = `Received: from x (${'('.repeat(5000)} [1.2.3.4]\n`.repeat(200);
  fast(() => analyzeInput({ kind: 'eml', value: `${received}From: a@b.test\n\nx` }));
});

test('un email con miles de enlaces se analiza rápido y con un número acotado', () => {
  const html = Array.from({ length: 20000 }, (_, i) => `<a href="http://1.2.3.4/login${i}">https://bank${i}.test</a>`).join('');
  let r;
  fast(() => { r = analyzeInput({ kind: 'eml', value: `From: a@b.test\nContent-Type: text/html\n\n${html}` }); }, 2000);
  assert.ok(r.email.links.length <= 200);
  assert.ok(r.findings.length < 100);
});

test('miles de adjuntos quedan acotados', () => {
  const parts = Array.from({ length: 2000 }, (_, i) => `--Z\nContent-Type: application/octet-stream; name="f${i}.exe"\n\nAA==\n`).join('');
  const r = analyzeInput({ kind: 'eml', value: `From: a@b.test\nContent-Type: multipart/mixed; boundary=Z\n\n${parts}--Z--` });
  assert.ok(r.email.attachments.length <= 100);
});

test('multipart anidado de forma recursiva no desborda la pila', () => {
  let body = 'x';
  for (let i = 0; i < 10000; i++) body = `--B${i}\nContent-Type: multipart/mixed; boundary=B${i + 1}\n\n${body}\n--B${i}--`;
  fast(() => analyzeInput({ kind: 'eml', value: `From: a@b.test\nContent-Type: multipart/mixed; boundary=B0\n\n${body}` }), 3000);
});

test('fuzzing: entradas repetitivas no tardan más de 1 s', () => {
  const pieces = ['=?utf-8?q?', '<a href=', '&#', 'http://a.b/(', '..', '@', ' on', 'style="', 'xn--', '\\u202e', '=\n', '-->', '<!--', '<script', '[1.1.1.1]', 'verifique su ', 'b'];
  for (const p of pieces) {
    const v = p.repeat(Math.ceil(200000 / p.length));
    for (const kind of ['eml', 'text', 'url']) {
      fast(() => analyzeInput({ kind, value: kind === 'eml' ? `From: ${v.slice(0, 5000)}\nSubject: ${v.slice(0, 5000)}\nContent-Type: text/html\n\n${v}` : v }));
    }
  }
});

// ---------- Engaños visuales (Trojan Source / bidi) ----------

test('reveal hace visibles los caracteres de control bidi e invisibles', () => {
  assert.equal(reveal('factura‮fdp.exe'), 'factura⟦U+202E⟧fdp.exe');
  assert.equal(reveal('Pay​Pal'), 'Pay⟦U+200B⟧Pal');
  assert.equal(reveal('normal'), 'normal');
});

// ---------- Contenido activo en el HTML ----------

test('enlaces javascript: se marcan como contenido peligroso', () => {
  assert.ok(detectHtml({ html: '<a href="javascript:alert(1)">ver factura</a>', text: '' }).some((f) => f.id === 'html.data-uri'));
  assert.ok(detectHtml({ html: '<a href=" JaVaScRiPt:alert(1)">x</a>', text: '' }).some((f) => f.id === 'html.data-uri'));
});

test('htmlToText nunca devuelve etiquetas ejecutables', () => {
  const out = htmlToText('<img src=x onerror=alert(1)><svg onload=alert(1)><script>alert(1)</script>hola');
  assert.doesNotMatch(out, /<|onerror|onload|alert/);
});

test('la CSP de index.html prohíbe toda conexión y la precarga de DNS está apagada', () => {
  const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
  const csp = html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1] ?? '';
  assert.match(csp, /(^|;)\s*connect-src 'none'\s*(;|$)/);
  assert.match(csp, /(^|;)\s*default-src 'none'\s*(;|$)/);
  assert.match(html, /<meta http-equiv="x-dns-prefetch-control" content="off">/);
});
