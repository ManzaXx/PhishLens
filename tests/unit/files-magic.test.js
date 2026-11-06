// Tipo real de un adjunto por sus primeros bytes, con un lector que nunca sale de rango.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reader } from '../../src/parser/files/bytes.js';
import { sniff } from '../../src/parser/files/magic.js';

const ascii = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const at = (size, offset, sig) => {
  const b = new Uint8Array(size);
  b.set(typeof sig === 'string' ? ascii(sig) : sig, offset);
  return b;
};

test('reader: little-endian y null fuera de rango', () => {
  const r = reader(Uint8Array.from([1, 2, 3, 4, 5]));
  assert.equal(r.length, 5);
  assert.equal(r.u8(0), 1);
  assert.equal(r.u16(0), 0x0201);
  assert.equal(r.u32(1), 0x05040302);
  assert.equal(r.ascii(0, 2), '\x01\x02');
  for (const bad of [-1, NaN, 5, 1.5, Infinity]) assert.equal(r.u8(bad), null, String(bad));
  assert.equal(r.u32(2), null);
  assert.equal(r.u16(4), null);
  assert.equal(r.ascii(3, 5), null);
  assert.equal(r.latin1(0, -1), null);
  assert.equal(r.latin1(5, 0), '');
});

test('sniff: un caso mínimo por tipo', () => {
  const pe = at(0x100, 0, 'MZ');
  pe.set([0x80, 0, 0, 0], 0x3c);
  pe.set(ascii('PE\0\0'), 0x80);
  const cases = [
    [pe, 'pe', 'Ejecutable de Windows'],
    [ascii('\x7FELF\x02\x01'), 'elf', 'Ejecutable de Linux'],
    [ascii('PK\x03\x04\x14\x00'), 'zip', 'Archivo ZIP'],
    [ascii('PK\x05\x06\0\0\0\0'), 'zip', 'Archivo ZIP'],
    [Uint8Array.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0]), 'ole', 'Documento OLE (Office antiguo)'],
    [ascii('%PDF-1.7\n'), 'pdf', 'PDF'],
    [ascii('\n\n  %PDF-1.4'), 'pdf', 'PDF'],
    [ascii('{\\rtf1\\ansi'), 'rtf', 'RTF'],
    [at(0x8806, 0x8801, 'CD001'), 'iso', 'Imagen de disco ISO'],
    [Uint8Array.from([0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0x00, 0]), 'lnk', 'Acceso directo de Windows'],
    [ascii('\xEF\xBB\xBF  <!DOCTYPE html><p>'), 'html', 'Página HTML'],
    [ascii('<HTML><body>'), 'html', 'Página HTML'],
    [ascii('\n<script>alert(1)</script>'), 'html', 'Página HTML'],
    [ascii('#!/bin/sh\necho'), 'script', 'Script'],
    [ascii('hola mundo'), 'unknown', 'Desconocido'],
  ];
  for (const [bytes, type, label] of cases) assert.deepEqual(sniff(bytes), { type, label }, type);
});

test('sniff: MZ con e_lfanew fuera del fichero sigue siendo PE; entradas mínimas no rompen', () => {
  const mz = at(0x40, 0, 'MZ');
  mz.set([0xff, 0xff, 0xff, 0x7f], 0x3c);
  assert.equal(sniff(mz).type, 'pe');
  assert.equal(sniff(ascii('MZ')).type, 'pe');
  assert.equal(sniff(ascii('PK\x03')).type, 'unknown');
  assert.equal(sniff(new Uint8Array(0)).type, 'unknown');
  assert.equal(sniff(at(2000, 1500, '%PDF-')).type, 'unknown');
});

test('sniff: «MZ» con e_lfanew dentro del fichero y sin firma PE no es un ejecutable', () => {
  const text = at(0x100, 0, 'MZ Logistica');
  text.set([0x10, 0, 0, 0], 0x3c);
  assert.equal(sniff(text).type, 'unknown');
});
