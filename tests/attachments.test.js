import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../src/detectors/attachments.js';

const att = (...names) => ({ attachments: names.map((filename) => ({ filename, contentType: 'application/octet-stream' })) });
const ids = (f) => f.map((x) => `${x.id}:${x.severity}`);

test('doble extensión', () => assert.deepEqual(ids(detect(att('factura.pdf.exe'))), ['attachments.double-extension:high']));
test('ejecutable', () => assert.deepEqual(ids(detect(att('nota.js'))), ['attachments.dangerous:high']));
test('documento con macros', () => assert.deepEqual(ids(detect(att('informe.docm'))), ['attachments.macro:medium']));
test('comprimido', () => assert.deepEqual(ids(detect(att('fotos.zip'))), ['attachments.archive:low']));
test('imagen normal', () => assert.deepEqual(detect(att('foto.jpg', 'Factura.PDF')), []));
test('mayúsculas y espacios', () => assert.deepEqual(ids(detect(att('FACTURA.PDF   .EXE'))), ['attachments.double-extension:high']));
test('carácter RTL que invierte la extensión', () => assert.deepEqual(ids(detect(att('factura‮fdp.exe'))), ['attachments.rtl-override:high']));
