// Revisión final del PR7: regresiones de nota, rodeos y falsos positivos encontrados al revisar la rama.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertWithinBudget } from '../helpers/timing.js';
import { analyzeInput } from '../../src/core/engine.js';
import { readZip } from '../../src/parser/files/zip.js';
import { readOle } from '../../src/parser/files/ole.js';
import { scanPdf } from '../../src/parser/files/pdf.js';
import { inspect } from '../../src/parser/files/index.js';
import { detect } from '../../src/detectors/attachments.js';
import { makeZip, makeOle } from '../helpers/files.js';

const b64 = (u) => Buffer.from(u).toString('base64').replace(/.{76}/g, '$&\n');
const enc = (s) => new TextEncoder().encode(s);
const eml = (name, bytes, body = 'Hola, es urgente: abre el documento hoy mismo o se cancelará tu cuenta.') => [
  'From: "Ana" <ana@example.com>', 'To: pablo@example.com', 'Subject: Documento', 'Date: Thu, 05 Nov 2026 08:41:00 +0100',
  'Message-ID: <a1@example.com>', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b"', '',
  '--b', 'Content-Type: text/plain; charset=utf-8', '', body, '',
  '--b', `Content-Type: application/octet-stream; name="${name}"`, `Content-Disposition: attachment; filename="${name}"`,
  'Content-Transfer-Encoding: base64', '', b64(bytes), '--b--', '',
].join('\n');
const run = (name, bytes, body) => analyzeInput({ kind: 'eml', value: eml(name, bytes, body) });
const file = (filename, bytes) => {
  const a = { filename, contentType: 'application/octet-stream', bytes, truncated: false, lossy: false };
  return { ...a, inspection: inspect(a) };
};
const ids = (attachments) => detect({ attachments }).map((f) => `${f.id}:${f.severity}`);

test('#1 las reglas nuevas de adjunto peligroso también cuentan para «adjunto con presión»', () => {
  const lnk = Uint8Array.from([0x4c, 0, 0, 0, 1, 0x14, 2, 0, ...new Array(70).fill(0)]);
  const exe = run('factura.exe', new Uint8Array(100));
  for (const [name, bytes] of [['factura.lnk', lnk], ['factura.iso', new Uint8Array(4000)], ['pedido.docm', makeZip([{ name: 'word/vbaProject.bin' }])],
    ['docs.zip', makeZip([{ name: 'factura.exe' }])], ['pago.html', enc('<html><script>URL.createObjectURL(new Blob([1]))</script>')]]) {
    const r = run(name, bytes);
    assert.ok(r.correlations.some((c) => c.id === 'attachment-pressure'), name);
    assert.ok(r.score >= exe.score - 5, `${name}: ${r.score} frente a ${exe.score}`);
  }
  // Un .docm con macros de verdad nunca puntúa menos que uno sin ellas.
  assert.ok(run('pedido.docm', makeZip([{ name: 'word/vbaProject.bin' }])).score >= run('pedido.docm', makeZip([{ name: 'word/document.xml' }])).score);
});

test('#2 una ruta larga dentro del ZIP no esconde el .exe; el nombre se recorta por delante', () => {
  const name = `${'x/'.repeat(140)}factura.exe`;
  const z = readZip(makeZip([{ name }]));
  assert.equal(z.entries[0].name.length, 260);
  assert.ok(z.entries[0].name.startsWith('…'));
  assert.ok(z.entries[0].name.endsWith('factura.exe'));
  assert.ok(ids([file('docs.zip', makeZip([{ name }]))]).includes('attachments.archive-executable:high'));
  assert.ok(ids([file('docs.zip', makeZip([{ name: `${'a'.repeat(65000)}.exe` }]))]).includes('attachments.archive-executable:high'));
});

test('#3 un directorio central que no cuadra no se da por vacío ni por completo', () => {
  const zeroTotal = readZip(makeZip([{ name: 'a.exe' }], { eocdTotal: 0 }));
  assert.equal(zeroTotal.complete, false);
  assert.deepEqual(zeroTotal.entries.map((e) => e.name), ['a.exe']);
  const badOffset = readZip(makeZip([{ name: 'leeme.txt' }, { name: 'b.exe' }], { cdOffset: 3 }));
  assert.equal(badOffset.complete, false);
  assert.ok(badOffset.entries.some((e) => e.name === 'b.exe'));
  const short = readZip(makeZip([{ name: 'a.txt' }], { eocdTotal: 0xffff }));
  assert.equal(short.complete, false);
  assert.equal(readZip(makeZip([{ name: 'a.txt' }])).complete, true);
  assert.equal(readZip(makeZip([])).complete, true);
  assert.ok(ids([file('docs.zip', makeZip([{ name: 'a.exe' }], { eocdTotal: 0 }))]).includes('attachments.archive-executable:high'));
});

test('#4 un PDF de 10 MB lleno de nombres cortos se revisa en menos de 2 s', () => {
  const bytes = enc(`%PDF-1.4\n${'/A'.repeat(5_000_000)}`);
  assert.deepEqual(assertWithinBudget(() => scanPdf(bytes), 2000, 'PDF de nombres cortos').tokens, []);
  const mixed = enc(`%PDF-1.4\n${'/AA /Fl /Type '.repeat(700_000)}`);
  assert.deepEqual(assertWithinBudget(() => scanPdf(mixed), 2000, 'PDF mixto').tokens, ['AA']);
});

test('#5 Office cifrado, .xlsb, Pages o XPS no son un tipo falso', () => {
  const encrypted = makeOle([{ name: 'EncryptionInfo', type: 2 }, { name: 'EncryptedPackage', type: 2 }]);
  for (const ext of ['xlsx', 'docx', 'pptx', 'xlsm']) assert.deepEqual(ids([file(`nominas.${ext}`, encrypted)]).filter((x) => x.includes('mismatch')), [], ext);
  for (const ext of ['xlsb', 'pages', 'numbers', 'key', 'xps', 'oxps', 'vsdm', '3mf']) {
    assert.deepEqual(ids([file(`a.${ext}`, makeZip([{ name: 'x.xml' }]))]).filter((x) => x.includes('mismatch')), [], ext);
  }
});

test('#6 un ZIP de logos SVG o de una web guardada no es «comprimido con un programa»', () => {
  const zip = makeZip([{ name: 'logo.svg' }, { name: 'index.html' }, { name: 'notas.one' }]);
  assert.deepEqual(ids([file('web.zip', zip)]), ['attachments.archive:low']);
  for (const inner of ['a.exe', 'a.js', 'a.vbs', 'a.lnk', 'a.hta', 'a.ps1', 'a.iso', 'a.msi', 'a.scr', 'a.bat']) {
    assert.ok(ids([file('x.zip', makeZip([{ name: inner }]))]).includes('attachments.archive-executable:high'), inner);
  }
});

test('#7 un OLE con el directorio a medias no dice «sin macros»', () => {
  const ole = makeOle([{ name: 'a', type: 2 }, { name: 'b', type: 2 }, { name: 'c', type: 2 }, { name: 'd', type: 2 }], { selfLoop: true });
  assert.equal(readOle(ole).complete, false);
  assert.equal(readOle(makeOle([{ name: 'WordDocument', type: 2 }])).complete, true);
});

test('#3 y #7 en la vista: un directorio a medias se dice, no se da por vacío ni «sin macros»', async () => {
  const { installDom } = await import('../helpers/dom.js');
  const dom = installDom();
  try {
    const { attachmentsPanel } = await import('../../src/ui/panels/attachments.js');
    const report = (name, bytes) => {
      const a = file(name, bytes);
      delete a.bytes;
      return { email: { attachments: [a] }, findings: [] };
    };
    const zipText = attachmentsPanel(report('a.zip', makeZip([{ name: 'a.exe' }], { eocdTotal: 0 }))).textContent;
    assert.doesNotMatch(zipText, /ZIP vacío/);
    assert.match(zipText, /no se pudo leer entero/i);
    assert.match(zipText, /a\.exe/);
    const oleText = attachmentsPanel(report('a.doc', makeOle([{ name: 'a', type: 2 }, { name: 'b', type: 2 }, { name: 'c', type: 2 }, { name: 'd', type: 2 }], { selfLoop: true }))).textContent;
    assert.doesNotMatch(oleText, /Sin macros/);
    assert.match(oleText, /no se puede asegurar/i);
  } finally {
    dom.restore();
  }
});
