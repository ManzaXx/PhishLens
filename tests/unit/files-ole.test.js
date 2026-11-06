// OLE2 (Office antiguo): solo se lee el directorio para saber si hay macros VBA.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readOle } from '../../src/parser/files/ole.js';
import { makeOle } from '../helpers/files.js';

const DOC = [{ name: 'WordDocument', type: 2 }, { name: '1Table', type: 2 }, { name: '\u0005SummaryInformation', type: 2 }];

test('readOle: un documento con VBA/dir tiene macros', () => {
  const o = readOle(makeOle([...DOC, { name: 'Macros', type: 1 }, { name: 'VBA', type: 1 }, { name: 'dir', type: 2 }, { name: '_VBA_PROJECT', type: 2 }]));
  assert.equal(o.ok, true);
  assert.equal(o.hasVba, true);
  assert.ok(o.streams.includes('WordDocument'));
  assert.ok(o.streams.includes('_VBA_PROJECT'));
  assert.equal(o.streams.includes('Root Entry'), false);
});

test('readOle: Excel con _VBA_PROJECT_CUR también; sin macros es false', () => {
  assert.equal(readOle(makeOle([{ name: 'Workbook', type: 2 }, { name: '_VBA_PROJECT_CUR', type: 1 }])).hasVba, true);
  const clean = readOle(makeOle(DOC));
  assert.equal(clean.ok, true);
  assert.equal(clean.hasVba, false);
  assert.equal(clean.streams.length, 3);
});

test('readOle: una cadena del directorio en bucle termina con lo leído', () => {
  const o = readOle(makeOle([...DOC, { name: 'a', type: 2 }, { name: 'b', type: 2 }, { name: 'VBA', type: 1 }], { selfLoop: true }));
  assert.equal(o.ok, true);
  assert.deepEqual(o.streams, ['WordDocument', '1Table', '\u0005SummaryInformation']);
  assert.equal(o.hasVba, false);
});

test('readOle: sector shift raro o cabecera cortada → ok:false', () => {
  assert.equal(readOle(makeOle(DOC, { shift: 20 })).ok, false);
  assert.equal(readOle(makeOle(DOC).slice(0, 300)).ok, false);
  assert.equal(readOle(new Uint8Array(0)).ok, false);
});
