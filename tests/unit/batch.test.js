import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeBatch, emailKey } from '../../src/core/batch.js';
import { sha256 } from '../../src/lib/sha256.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';

const MB = 1024 * 1024;
const file = (name, text, size = text.length) => ({ name, size, text: async () => text });
const sample = (id) => SAMPLE_TEXTS[id];
const noYield = { yieldFn: async () => {} };

test('emailKey es el SHA-256 del texto crudo con los saltos de línea normalizados', () => {
  assert.equal(emailKey('abc'), sha256('abc'));
  assert.equal(emailKey('a\r\nb\rc'), sha256('a\nb\nc'));
});

test('tres muestras: tres entradas ordenadas por clave, sin saltos ni aviso, con progreso', async () => {
  const progress = [];
  const files = ['03-phishing-banco', '04-phishing-correos', '05-phishing-microsoft365'].map((id) => file(`${id}.eml`, sample(id)));
  const out = await analyzeBatch(files, { ...noYield, onProgress: (i, n) => progress.push([i, n]) });
  assert.equal(out.entries.length, 3);
  assert.deepEqual(out.skipped, []);
  assert.equal(out.warning, null);
  assert.deepEqual(progress, [[1, 3], [2, 3], [3, 3]]);
  const keys = out.entries.map((e) => e.key);
  assert.deepEqual(keys, [...keys].sort());
  for (const e of out.entries) {
    assert.equal(e.key, emailKey(e.report ? sample(e.name.replace('.eml', '')) : ''));
    assert.ok(e.report.level);
  }
});

test('51 correos distintos: se analizan 50 y se avisa', async () => {
  const files = Array.from({ length: 51 }, (_, i) => file(`m${String(i).padStart(2, '0')}.eml`, `From: a${i}@x.test\r\nSubject: ${i}\r\n\r\nhola ${i}`));
  const out = await analyzeBatch(files, noYield);
  assert.equal(out.entries.length, 50);
  assert.deepEqual(out.skipped, [{ name: 'm50.eml', reason: 'limite' }]);
  assert.equal(out.warning, 'Se han analizado 50 de 51 correos: el máximo es 50 por lote y 100 MB en total.');
});

test('más de 100 MB en total: el que no cabe se salta por límite', async () => {
  const files = ['a', 'b', 'c'].map((n) => file(`${n}.eml`, `From: ${n}@x.test\r\n\r\n${n}`, 40 * MB));
  const out = await analyzeBatch(files, { ...noYield });
  // 40 MB pasa del límite por fichero (25 MB): se usa un tamaño válido para probar el total.
  assert.equal(out.entries.length, 0);
  const ok = Array.from({ length: 5 }, (_, i) => file(`f${i}.eml`, `From: f${i}@x.test\r\n\r\n${i}`, 24 * MB));
  const out2 = await analyzeBatch(ok, noYield);
  assert.equal(out2.entries.length, 4);
  assert.deepEqual(out2.skipped, [{ name: 'f4.eml', reason: 'limite' }]);
  assert.match(out2.warning, /^Se han analizado 4 de 5 correos/);
});

test('el mismo correo con dos nombres cuenta una vez y se marca como duplicado', async () => {
  const out = await analyzeBatch([file('b.eml', sample('03-phishing-banco')), file('a.eml', sample('03-phishing-banco'))], noYield);
  assert.equal(out.entries.length, 1);
  assert.equal(out.entries[0].name, 'a.eml');
  assert.deepEqual(out.skipped, [{ name: 'b.eml', reason: 'duplicado' }]);
});

test('lote mezclado: se analiza lo válido y se dice qué se salta y por qué', async () => {
  const boom = () => { throw new Error('roto'); };
  let calls = 0;
  const analyze = (input) => {
    calls++;
    if (input.value.includes('BOOM')) boom();
    return { level: 'safe', score: 0 };
  };
  const files = [
    file('x.pdf', '%PDF-1.7'),
    file('grande.eml', 'From: a@b.test\r\n\r\nx', 30 * MB),
    file('vacio.eml', '  \n'),
    file('roto.eml', 'From: a@b.test\r\n\r\nBOOM'),
    file('bueno.eml', sample('04-phishing-correos')),
    { name: 'raw', size: 10, type: 'message/rfc822', text: async () => 'From: r@b.test\r\n\r\nok' },
  ];
  const out = await analyzeBatch(files, { ...noYield, analyze });
  assert.deepEqual(out.entries.map((e) => e.name).sort(), ['bueno.eml', 'raw']);
  assert.deepEqual([...out.skipped].sort((a, b) => a.name.localeCompare(b.name)), [
    { name: 'grande.eml', reason: 'tamano' },
    { name: 'roto.eml', reason: 'error' },
    { name: 'vacio.eml', reason: 'vacio' },
    { name: 'x.pdf', reason: 'tipo' },
  ]);
  assert.equal(out.warning, null);
  assert.equal(calls, 3);
});

test('el orden de selección no cambia el resultado', async () => {
  const ids = ['03-phishing-banco', '04-phishing-correos', '05-phishing-microsoft365', '03-phishing-banco'];
  const make = () => ids.map((id, i) => file(`${i}-${id}.eml`, sample(id)));
  const a = await analyzeBatch(make(), noYield);
  const b = await analyzeBatch(make().reverse(), noYield);
  assert.deepEqual(a.entries.map((e) => [e.key, e.name]), b.entries.map((e) => [e.key, e.name]));
  assert.deepEqual(a.skipped, b.skipped);
});

test('cede el hilo entre correos y se puede abortar', async () => {
  let yields = 0;
  const files = ['03-phishing-banco', '04-phishing-correos', '05-phishing-microsoft365'].map((id) => file(`${id}.eml`, sample(id)));
  await analyzeBatch(files, { yieldFn: async () => { yields++; } });
  assert.equal(yields, 3);
  const controller = new AbortController();
  const out = await analyzeBatch(files, { yieldFn: async () => controller.abort(), signal: controller.signal });
  assert.equal(out, null);
});

test('un archivo que no se puede leer se salta como error y el resto sigue', async () => {
  const bad = { name: 'b.eml', size: 10, text: async () => { throw Object.assign(new Error('x'), { name: 'NotReadableError' }); } };
  const out = await analyzeBatch([file('a.eml', sample('03-phishing-banco')), bad, file('c.eml', sample('04-phishing-correos'))], noYield);
  assert.equal(out.entries.length, 2);
  assert.deepEqual(out.skipped, [{ name: 'b.eml', reason: 'error' }]);
});

test('el mismo correo con saltos de línea LF o CRLF es el mismo correo', async () => {
  const crlf = sample('03-phishing-banco').replace(/\r?\n/g, '\r\n');
  const lf = crlf.replace(/\r\n/g, '\n');
  assert.equal(emailKey(crlf), emailKey(lf));
  const out = await analyzeBatch([file('a.eml', crlf), file('b.eml', lf)], noYield);
  assert.equal(out.entries.length, 1);
  assert.deepEqual(out.skipped, [{ name: 'b.eml', reason: 'duplicado' }]);
});
