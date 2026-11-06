// inspect(): junta los lectores de formato y el parser la guarda en cada adjunto.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { inspect } from '../../src/parser/files/index.js';
import { analyzeInput } from '../../src/core/engine.js';
import { makeZip, makeOle } from '../helpers/files.js';

const MZ = (() => { const b = new Uint8Array(64); b[0] = 0x4d; b[1] = 0x5a; b[0x3c] = 0xff; b[0x3f] = 0x7f; return b; })();
const att = (filename, bytes, extra = {}) => ({ filename, contentType: 'application/octet-stream', bytes, truncated: false, lossy: false, ...extra });

test('inspect: un .pdf que en realidad es un ejecutable', () => {
  const i = inspect(att('factura.pdf', MZ));
  assert.equal(i.realType, 'pe');
  assert.equal(i.realLabel, 'Ejecutable de Windows');
  assert.equal(i.declaredExt, 'pdf');
  assert.equal(i.partial, false);
  assert.deepEqual([i.zip, i.ole, i.pdf, i.html], [null, null, null, null]);
});

test('inspect: un .docm con word/vbaProject.bin', () => {
  const i = inspect(att('Informe.DOCM', makeZip([{ name: '[Content_Types].xml' }, { name: 'word/document.xml' }, { name: 'word/vbaProject.bin' }])));
  assert.equal(i.realType, 'zip');
  assert.equal(i.declaredExt, 'docm');
  assert.equal(i.zip.ok, true);
  assert.equal(i.zip.vbaProject, true);
  assert.equal(inspect(att('a.zip', makeZip([{ name: 'a.txt' }]))).zip.vbaProject, false);
});

test('inspect: OLE, PDF y HTML llevan su lectura', () => {
  assert.equal(inspect(att('a.doc', makeOle([{ name: 'Macros', type: 1 }]))).ole.hasVba, true);
  assert.deepEqual(inspect(att('a.pdf', new TextEncoder().encode('%PDF-1.4 /JS (x)'))).pdf.tokens, ['JavaScript']);
  assert.equal(inspect(att('a.html', new TextEncoder().encode('<html><script>new Blob([1])</script>'))).html.suspicious, true);
  assert.equal(inspect(att('sin-extension', MZ)).declaredExt, null);
});

test('inspect: un adjunto recortado o ilegible no se lee por dentro', () => {
  for (const extra of [{ truncated: true }, { lossy: true }]) {
    const i = inspect(att('a.zip', makeZip([{ name: 'x.exe' }]), extra));
    assert.equal(i.partial, true);
    assert.equal(i.zip, null);
  }
});

test('el parser guarda la inspección y la muestra 06 conserva su nivel', () => {
  const raw = readFileSync(new URL('../../samples/06-phishing-factura-adjunto.eml', import.meta.url), 'utf8');
  const report = analyzeInput({ kind: 'eml', value: raw });
  const golden = JSON.parse(readFileSync(new URL('./__golden__/samples.json', import.meta.url), 'utf8'));
  assert.equal(report.level, golden['06-phishing-factura-adjunto'].level);
  const [a] = report.email.attachments;
  assert.ok(a.inspection);
  assert.equal(typeof a.inspection.realType, 'string');
});
