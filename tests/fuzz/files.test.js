// Fuzzing por formato de adjunto (spec 2.3, PR7): se mutan ZIP, OLE, PDF y HTML válidos
// y inspect() no puede lanzar ni tardar. Semilla fija; más casos con FUZZ_ITER.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from '../../src/parser/files/index.js';
import { readZip } from '../../src/parser/files/zip.js';
import { readOle } from '../../src/parser/files/ole.js';
import { scanPdf } from '../../src/parser/files/pdf.js';
import { makeZip, makeOle } from '../helpers/files.js';
import { rng, pick } from '../helpers/rng.js';
import { withinBudget, percentiles } from '../helpers/timing.js';

const ITER = Number(process.env.FUZZ_ITER ?? 2000);
const SEED = Number(process.env.FUZZ_SEED ?? 20261106);
const MAX_MS = 2000;
const enc = (s) => new TextEncoder().encode(s);

const BASES = [
  ['zip', 'docs.zip', makeZip([{ name: 'a.pdf' }, { name: 'b.exe', encrypted: true }, { name: 'word/vbaProject.bin' }, { name: 'ü.txt', utf8: false }])],
  ['ole', 'a.doc', makeOle([{ name: 'WordDocument', type: 2 }, { name: 'Macros', type: 1 }, { name: 'VBA', type: 1 }, { name: 'dir', type: 2 }, { name: '_VBA_PROJECT', type: 2 }, { name: 'x', type: 2 }])],
  ['pdf', 'a.pdf', enc('%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /AA << >> >> endobj 2 0 obj << /S /J#61vaScript /JS (x) /Filter /FlateDecode >> endobj\n%%EOF')],
  ['html', 'a.html', enc('<!doctype html><script>var b=new Blob([atob(d)]);a.href=URL.createObjectURL(b);a.download="x.iso"</script>')],
];

const MUTATIONS = {
  bytes(b, r) {
    if (!b.length) return b;
    const out = b.slice();
    for (let i = 0; i < 1 + pick(r, 16); i++) out[pick(r, out.length)] = pick(r, 256);
    return out;
  },
  cut(b, r) { return b.slice(0, pick(r, b.length + 1)); },
  repeat(b, r) {
    if (!b.length) return b;
    const a = pick(r, b.length);
    const block = b.slice(a, a + 1 + pick(r, 128));
    const out = new Uint8Array(b.length + block.length * 8);
    out.set(b.subarray(0, a));
    for (let i = 0; i < 8; i++) out.set(block, a + i * block.length);
    out.set(b.subarray(a), a + block.length * 8);
    return out;
  },
  bigOffset(b, r) {
    if (b.length < 4) return b;
    const out = b.slice();
    const o = pick(r, Math.max(1, out.length - 4)) & ~3;
    out.set([0xff, 0xff, 0xff, 0xff], o);
    return out;
  },
  zeroOffset(b, r) {
    if (b.length < 4) return b;
    const out = b.slice();
    const o = pick(r, Math.max(1, out.length - 4)) & ~3;
    out.set([0, 0, 0, 0], o);
    return out;
  },
};
const NAMES = Object.keys(MUTATIONS);

const slowMessage = (where, runs) => `${where}: más de ${MAX_MS} ms en todos los intentos (${runs.map((ms) => Math.round(ms)).join(', ')} ms)`;

function check(where, filename, bytes, times) {
  let timing;
  try {
    timing = withinBudget(() => inspect({ filename, contentType: 'application/octet-stream', bytes, truncated: false, lossy: false }), MAX_MS);
  } catch (err) {
    assert.fail(`${where}: lanzó ${err?.stack ?? err}`);
  }
  const out = timing.value;
  times?.push(timing.runs[0]);
  assert.ok(timing.ok, slowMessage(where, timing.runs));
  assert.equal(typeof out.realType, 'string', where);
  if (out.zip) assert.ok(out.zip.entries.length <= 1000, where);
}

test(`fuzzing: ${ITER} adjuntos mutados no rompen inspect()`, (t) => {
  const r = rng(SEED);
  const times = [];
  for (let i = 0; i < ITER; i++) {
    const [kind, filename, base] = BASES[pick(r, BASES.length)];
    let bytes = base;
    const applied = [];
    for (let k = 0; k < 1 + pick(r, 3); k++) {
      const name = NAMES[pick(r, NAMES.length)];
      bytes = MUTATIONS[name](bytes, r);
      applied.push(name);
    }
    check(`caso ${i} (semilla ${SEED}, ${kind}, ${applied.join('+')})`, filename, bytes, times);
  }
  const p = percentiles(times);
  t.diagnostic(`inspect: p50 ${p.p50.toFixed(2)} ms · p99 ${p.p99.toFixed(2)} ms · máx ${p.max.toFixed(2)} ms (primer intento)`);
});

const timed = (label, fn) => {
  const r = withinBudget(fn, MAX_MS);
  assert.ok(r.ok, slowMessage(label, r.runs));
  return r.value;
};

test('casos fijos adversarios terminan rápido y sin lanzar', () => {
  // Cadena del directorio OLE en bucle.
  assert.equal(timed('FAT en ciclo', () => readOle(makeOle([{ name: 'a', type: 2 }, { name: 'b', type: 2 }, { name: 'c', type: 2 }, { name: 'd', type: 2 }], { selfLoop: true }))).ok, true);
  // EOCD que promete 65.535 entradas.
  assert.equal(timed('EOCD 65.535', () => readZip(makeZip([{ name: 'a' }], { eocdTotal: 0xffff }))).entries.length, 1);

  // 10 MB de cabeceras centrales con un EOCD que dice que todo es directorio.
  const big = new Uint8Array(10 * 1024 * 1024);
  for (let o = 0; o + 46 <= big.length - 22; o += 46) big.set([0x50, 0x4b, 0x01, 0x02], o);
  const v = new DataView(big.buffer);
  const e = big.length - 22;
  big.set([0x50, 0x4b, 0x05, 0x06], e);
  v.setUint16(e + 10, 0xffff, true);
  v.setUint32(e + 12, e, true);
  v.setUint32(e + 16, 0, true);
  const z = timed('10 MB de PK\\x01\\x02', () => readZip(big));
  assert.equal(z.entries.length, 1000);
  assert.equal(z.truncated, true);

  // 10 MB de «/» y 10 MB de nombres #xx.
  assert.deepEqual(timed('10 MB de /', () => scanPdf(new Uint8Array(10 * 1024 * 1024).fill(0x2f))).tokens, []);
  assert.deepEqual(timed('10 MB de #41', () => scanPdf(enc(`/${'#41'.repeat(3_000_000)}`))).tokens, []);

  // OLE de 10 MB con la cadena del directorio recorriendo todos los sectores.
  const ole = makeOle([{ name: 'a', type: 2 }]);
  const huge = new Uint8Array(10 * 1024 * 1024);
  huge.set(ole);
  const hv = new DataView(huge.buffer);
  for (let s = 1; s < 127; s++) hv.setUint32(512 + s * 4, s + 1, true);
  timed('OLE con cadena larga', () => readOle(huge));

  // Todo a 0xFF en la cabecera OLE y offsets imposibles.
  const ff = makeOle([{ name: 'a', type: 2 }]);
  ff.fill(0xff, 8, 512);
  assert.doesNotThrow(() => readOle(ff));
});
