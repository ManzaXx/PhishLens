// Pruebas de seguridad: entradas hostiles que intentan romper, bloquear o engañar a PhishLens.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertWithinBudget } from '../helpers/timing.js';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEml, parseAddress } from '../../src/parser/eml.js';
import { decodeEntities, htmlToText } from '../../src/parser/html.js';
import { analyzeInput } from '../../src/core/engine.js';
import { reveal } from '../../src/lib/text.js';
import { detect as detectHtml } from '../../src/detectors/html.js';

// Presupuesto con reintento (tests/helpers/timing.js): una entrada hostil lenta lo es en todos los intentos.
const fast = (fn, ms = 1000) => assertWithinBudget(fn, ms, 'entrada hostil');

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
  assert.equal(reveal('factura\u202Efdp.exe'), 'factura⟦U+202E⟧fdp.exe');
  assert.equal(reveal('Pay\u200BPal'), 'Pay⟦U+200B⟧Pal');
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
  // Desde la 3.2 (ADR 0007) el análisis va en un worker blob:, que hereda esta misma CSP (tests/e2e/worker.e2e.js);
  // la única política de Trusted Types permitida es la que crea ese worker, y solo acepta blob: del propio origen.
  // 'self' en worker-src está solo porque Firefox comprueba contra worker-src los módulos que importa el worker
  // (el motor, del mismo origen); new Worker con una URL sigue sin ser posible: Trusted Types exige la política,
  // y la política solo acepta blob:.
  for (const d of ["worker-src blob: 'self'", "script-src 'self'", "require-trusted-types-for 'script'", 'trusted-types phishlens-worker', "object-src 'none'", "base-uri 'none'", "form-action 'none'"]) {
    assert.ok(csp.split(';').map((x) => x.trim()).includes(d), `falta ${d}`);
  }
  assert.doesNotMatch(csp, /worker-src[^;]*(https?:|data:|\*|'unsafe)/, 'el worker nunca puede nacer de una URL remota ni de data:');
  assert.doesNotMatch(csp, /trusted-types[^;]*'allow-duplicates'/, 'una segunda política con el mismo nombre debe fallar');
  assert.doesNotMatch(csp, /unsafe-(inline|eval)/);
});

test('el código de la web no escribe HTML ni evalúa texto, y no tiene dependencias', () => {
  const walk = (dir) => readdirSync(dir, { withFileTypes: true })
    .flatMap((d) => (d.isDirectory() ? walk(join(dir, d.name)) : d.name.endsWith('.js') ? [join(dir, d.name)] : []));
  const src = fileURLToPath(new URL('../../src', import.meta.url));
  for (const file of walk(src)) {
    const code = readFileSync(file, 'utf8');
    assert.doesNotMatch(code, /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|\beval\(|new Function\(/, file);
    for (const [, spec] of code.matchAll(/^\s*(?:import|export)[^'"]*from\s+['"]([^'"]+)['"]/gm)) assert.ok(spec.startsWith('.'), `${file} importa ${spec}`);
  }
  const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.dependencies, undefined, 'la web no tiene dependencias en ejecución');
});
