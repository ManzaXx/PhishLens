import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../../src/detectors/attachments.js';

const att = (...names) => ({ attachments: names.map((filename) => ({ filename, contentType: 'application/octet-stream' })) });
const ids = (f) => f.map((x) => `${x.id}:${x.severity}`);

test('doble extensión', () => assert.deepEqual(ids(detect(att('factura.pdf.exe'))), ['attachments.double-extension:high']));
test('ejecutable', () => assert.deepEqual(ids(detect(att('nota.js'))), ['attachments.dangerous:high']));
test('documento con macros', () => assert.deepEqual(ids(detect(att('informe.docm'))), ['attachments.macro:medium']));
test('comprimido', () => assert.deepEqual(ids(detect(att('fotos.zip'))), ['attachments.archive:low']));
test('imagen normal', () => assert.deepEqual(detect(att('foto.jpg', 'Factura.PDF')), []));
test('mayúsculas y espacios', () => assert.deepEqual(ids(detect(att('FACTURA.PDF   .EXE'))), ['attachments.double-extension:high']));
test('carácter RTL que invierte la extensión', () => assert.deepEqual(ids(detect(att('factura‮fdp.exe'))), ['attachments.rtl-override:high']));

// ---------- PR7: reglas sobre el contenido (inspection) ----------
import { inspect } from '../../src/parser/files/index.js';
import { makeZip, makeOle } from '../helpers/files.js';
import { PLAIN } from '../../src/data/plain.js';
import { techniquesFor } from '../../src/data/mitre.js';

const enc = (s) => new TextEncoder().encode(s);
const MZ = (() => { const b = new Uint8Array(64); b[0] = 0x4d; b[1] = 0x5a; b[0x3c] = 0xff; b[0x3f] = 0x7f; return b; })();
const file = (filename, bytes, extra = {}) => {
  const a = { filename, contentType: 'application/octet-stream', bytes, truncated: false, lossy: false, ...extra };
  return { ...a, inspection: inspect(a) };
};
const scan = (...files) => ids(detect({ attachments: files }));
const NEW_RULES = ['type-mismatch', 'archive-executable', 'encrypted-archive', 'pdf-active', 'ole-macro', 'html-smuggling', 'disk-image', 'lnk'];

test('type-mismatch: un .pdf que es un ejecutable es grave; un .pdf que es un ZIP, medio', () => {
  assert.deepEqual(scan(file('factura.pdf', MZ)), ['attachments.type-mismatch:high']);
  assert.deepEqual(scan(file('factura.pdf', makeZip([{ name: 'a.txt' }]))), ['attachments.type-mismatch:medium']);
  assert.deepEqual(scan(file('foto.jpg', enc('<html><body>hola'))), ['attachments.type-mismatch:high']);
});

test('type-mismatch: Office moderno y otros formatos ZIP no lo son', () => {
  for (const ext of ['docx', 'xlsx', 'pptx', 'odt', 'ods', 'epub', 'apk', 'zip']) {
    assert.deepEqual(scan(file(`a.${ext}`, makeZip([{ name: 'x.xml' }]))).filter((x) => x.includes('type-mismatch')), [], ext);
  }
  assert.deepEqual(scan(file('a.doc', makeOle([{ name: 'WordDocument', type: 2 }]))), []);
  assert.deepEqual(scan(file('a.pdf', enc('%PDF-1.4 hola'))), []);
  assert.deepEqual(scan(file('nota.txt', enc('hola'))), []);
});

test('archive-executable y encrypted-archive', () => {
  assert.deepEqual(scan(file('docs.zip', makeZip([{ name: 'leeme.txt' }, { name: 'carpeta/Factura.pdf.exe' }]))), ['attachments.archive:low', 'attachments.archive-executable:high']);
  assert.deepEqual(scan(file('docs.zip', makeZip([{ name: 'acceso.LNK' }]))), ['attachments.archive:low', 'attachments.archive-executable:high']);
  assert.deepEqual(scan(file('docs.zip', makeZip([{ name: 'a.pdf', encrypted: true }]))), ['attachments.archive:low', 'attachments.encrypted-archive:medium']);
  assert.deepEqual(scan(file('docs.zip', makeZip([{ name: 'a.pdf' }]))), ['attachments.archive:low']);
});

test('pdf-active: Launch grave, JavaScript medio, OpenAction solo leve, URI solo nada', () => {
  assert.deepEqual(scan(file('a.pdf', enc('%PDF-1.7 /Launch'))), ['attachments.pdf-active:high']);
  assert.deepEqual(scan(file('a.pdf', enc('%PDF-1.7 /EmbeddedFiles /JS'))), ['attachments.pdf-active:high']);
  assert.deepEqual(scan(file('a.pdf', enc('%PDF-1.7 /OpenAction /JavaScript'))), ['attachments.pdf-active:medium']);
  assert.deepEqual(scan(file('a.pdf', enc('%PDF-1.7 /OpenAction [3 0 R /Fit]'))), ['attachments.pdf-active:low']);
  assert.deepEqual(scan(file('a.pdf', enc('%PDF-1.7 /URI (https://x.test)'))), []);
});

test('ole-macro sustituye a macro y no se duplica', () => {
  assert.deepEqual(scan(file('informe.doc', makeOle([{ name: 'Macros', type: 1 }]))), ['attachments.ole-macro:high']);
  assert.deepEqual(scan(file('informe.docm', makeZip([{ name: 'word/vbaProject.bin' }]))), ['attachments.ole-macro:high']);
  // Un .docm sin proyecto VBA sigue siendo el aviso por nombre.
  assert.deepEqual(scan(file('informe.docm', makeZip([{ name: 'word/document.xml' }]))), ['attachments.macro:medium']);
});

test('html-smuggling', () => {
  assert.deepEqual(scan(file('pago.htm', enc('<html><script>a.href=URL.createObjectURL(new Blob([x]))</script>'))), ['attachments.dangerous:high', 'attachments.html-smuggling:high']);
  assert.deepEqual(scan(file('pago.htm', enc('<html><p>hola</p>'))), ['attachments.dangerous:high']);
});

test('disk-image y lnk: por extensión o por contenido, en lugar del aviso genérico', () => {
  assert.deepEqual(scan(file('factura.iso', new Uint8Array(10))), ['attachments.disk-image:high']);
  assert.deepEqual(scan(file('factura.vhdx', new Uint8Array(10))), ['attachments.disk-image:high']);
  const iso = new Uint8Array(0x8806); iso.set(enc('CD001'), 0x8001);
  assert.deepEqual(scan(file('factura.img', iso)), ['attachments.disk-image:high']);
  assert.deepEqual(scan(file('factura.lnk', new Uint8Array(4))), ['attachments.lnk:high']);
  const lnk = Uint8Array.from([0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0x00, 0]);
  assert.deepEqual(scan(file('factura.pdf', lnk)), ['attachments.type-mismatch:high', 'attachments.lnk:high']);
});

test('un adjunto recortado o ilegible solo da las reglas por nombre', () => {
  const zip = makeZip([{ name: 'x.exe', encrypted: true }]);
  assert.deepEqual(scan(file('docs.zip', zip, { truncated: true })), ['attachments.archive:low']);
  assert.deepEqual(scan(file('factura.pdf', MZ, { lossy: true })), []);
  assert.deepEqual(scan(file('a.iso', new Uint8Array(3), { truncated: true })), ['attachments.disk-image:high']);
});

test('sin inspection (entrada antigua) el detector sigue funcionando por nombre', () => {
  assert.deepEqual(ids(detect(att('fotos.zip'))), ['attachments.archive:low']);
});

test('cada regla nueva tiene texto llano y técnica ATT&CK', () => {
  for (const r of NEW_RULES) {
    assert.ok(Object.hasOwn(PLAIN, `attachments.${r}`), r);
    assert.ok(techniquesFor(`attachments.${r}`).length > 0, r);
  }
  assert.equal(techniquesFor('attachments.type-mismatch')[0].id, 'T1036.008');
  assert.equal(techniquesFor('attachments.html-smuggling')[0].id, 'T1027.006');
  assert.equal(techniquesFor('attachments.encrypted-archive')[0].id, 'T1027.013');
  assert.equal(techniquesFor('attachments.disk-image')[0].id, 'T1553.005');
  assert.equal(techniquesFor('attachments.ole-macro')[0].id, 'T1059.005');
});
