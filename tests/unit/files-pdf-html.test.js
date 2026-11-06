// PDF: nombres que activan acciones (sin descomprimir flujos). HTML: señales de smuggling.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanPdf } from '../../src/parser/files/pdf.js';
import { htmlSmuggling } from '../../src/parser/files/html.js';

const enc = (s) => new TextEncoder().encode(s);
const pdf = (body) => enc(`%PDF-1.7\n${body}\n%%EOF`);

test('scanPdf: /OpenAction + /JS cuenta como JavaScript y respeta el orden fijo', () => {
  const r = scanPdf(pdf('1 0 obj << /OpenAction 2 0 R >> endobj 2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj'));
  assert.deepEqual(r.tokens, ['JavaScript', 'OpenAction']);
  assert.equal(r.compressedStreams, 0);
});

test('scanPdf: nombres ofuscados con #xx se deshacen antes de comparar', () => {
  assert.deepEqual(scanPdf(pdf('<< /S /J#61vaScript /J#53 (x) >>')).tokens, ['JavaScript']);
  assert.deepEqual(scanPdf(pdf('<< /#4C#61unch << /F (cmd.exe) >> >>')).tokens, ['Launch']);
});

test('scanPdf: Launch solo, EmbeddedFiles, URI, AA y flujos comprimidos', () => {
  assert.deepEqual(scanPdf(pdf('<< /Launch << /F (x) >> >>')).tokens, ['Launch']);
  assert.deepEqual(scanPdf(pdf('<< /Names << /EmbeddedFiles 3 0 R >> /AA << >> /URI (https://x.test) >>')).tokens, ['EmbeddedFile', 'URI', 'AA']);
  const r = scanPdf(pdf('<< /Filter /FlateDecode /Length 3 >> stream\nxyz\nendstream << /Filter [/ASCII85Decode /Fl] >>'));
  assert.equal(r.compressedStreams, 3);
});

test('scanPdf: un PDF sin nada activo y 10 MB de «/» en menos de 2 s', () => {
  assert.deepEqual(scanPdf(pdf('<< /Type /Page /Contents 4 0 R >>')).tokens, []);
  const start = performance.now();
  assert.deepEqual(scanPdf(new Uint8Array(10 * 1024 * 1024).fill(0x2f)).tokens, []);
  const long = new Uint8Array(10 * 1024 * 1024).fill(0x41);
  long[0] = 0x2f;
  assert.deepEqual(scanPdf(long).tokens, []);
  assert.ok(performance.now() - start < 2000);
});

test('htmlSmuggling: Blob + createObjectURL dentro de un script', () => {
  const r = htmlSmuggling(enc('<html><script>const b = new Blob([atob(d)]); a.href = URL.createObjectURL(b); a.download = "f.iso";</script>'));
  assert.equal(r.suspicious, true);
  assert.deepEqual(r.markers, ['new Blob(', 'URL.createObjectURL', 'atob + download']);
  assert.deepEqual(htmlSmuggling(enc('<script>navigator.msSaveOrOpenBlob(b)</script>')).markers, ['msSaveOrOpenBlob']);
});

test('htmlSmuggling: las palabras sin <script> no bastan', () => {
  assert.deepEqual(htmlSmuggling(enc('<p>Usa new Blob( y URL.createObjectURL para…</p>')), { suspicious: false, markers: [] });
  assert.deepEqual(htmlSmuggling(enc('<script>console.log(1)</script>')), { suspicious: false, markers: [] });
});
