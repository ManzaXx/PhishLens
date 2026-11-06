// ZIP leído solo por su directorio central: nunca se descomprime nada.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readZip } from '../../src/parser/files/zip.js';
import { makeZip } from '../helpers/files.js';

test('readZip: nombres, tamaños y cifrado de cada entrada', () => {
  const z = readZip(makeZip([{ name: 'factura.pdf', size: 1200 }, { name: 'factura.pdf.exe', size: 50, encrypted: true }]));
  assert.equal(z.ok, true);
  assert.equal(z.truncated, false);
  assert.deepEqual(z.entries, [
    { name: 'factura.pdf', encrypted: false, size: 1200 },
    { name: 'factura.pdf.exe', encrypted: true, size: 50 },
  ]);
});

test('readZip: ZIP vacío', () => {
  assert.deepEqual(readZip(makeZip([])), { ok: true, entries: [], truncated: false, reason: null });
});

test('readZip: el EOCD dice 65.535 entradas y hay dos', () => {
  const z = readZip(makeZip([{ name: 'a.txt' }, { name: 'b.txt' }], { eocdTotal: 0xffff }));
  assert.equal(z.ok, true);
  assert.deepEqual(z.entries.map((e) => e.name), ['a.txt', 'b.txt']);
});

test('readZip: directorio fuera del fichero, sin EOCD o ZIP64 → ok:false con motivo', () => {
  assert.deepEqual(readZip(makeZip([{ name: 'a' }], { cdOffset: 0x7fffffff })), { ok: false, entries: [], truncated: false, reason: 'directorio fuera del fichero' });
  assert.equal(readZip(new TextEncoder().encode('PK\x03\x04 nada más')).reason, 'sin directorio central');
  assert.equal(readZip(makeZip([{ name: 'a' }], { cdOffset: 0xffffffff })).reason, 'ZIP64 no soportado');
  assert.equal(readZip(new Uint8Array(0)).ok, false);
});

test('readZip: un comentario de 65.535 bytes tras el EOCD', () => {
  const z = readZip(makeZip([{ name: 'a.exe' }], { comment: new Uint8Array(0xffff).fill(0x20) }));
  assert.deepEqual(z.entries.map((e) => e.name), ['a.exe']);
});

test('readZip: nombres hostiles se conservan (recortados) para que la vista los revele', () => {
  const z = readZip(makeZip([
    { name: '../../x.exe' },
    { name: 'factura‮fdp.exe' },
    { name: Uint8Array.from([0x6d, 0x81, 0x6c, 0x6c, 0x65, 0x72, 0x2e, 0x74, 0x78, 0x74]) },
    { name: 'a'.repeat(65000) },
  ]));
  assert.deepEqual(z.entries.slice(0, 3).map((e) => e.name), ['../../x.exe', 'factura‮fdp.exe', 'müller.txt']);
  assert.equal(z.entries[3].name.length, 260);
});

test('readZip: como mucho 1.000 entradas', () => {
  const z = readZip(makeZip(Array.from({ length: 1500 }, (_, i) => ({ name: `f${i}.txt` }))));
  assert.equal(z.entries.length, 1000);
  assert.equal(z.truncated, true);
});
