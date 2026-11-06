// Constructores de ficheros mínimos para probar los lectores de adjuntos.
// Solo los usan los tests y tools/gen-samples.mjs: no contienen código ejecutable.

const enc = (s) => (typeof s === 'string' ? new TextEncoder().encode(s) : s);

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function le(size, fields) {
  const b = new Uint8Array(size);
  const v = new DataView(b.buffer);
  for (const [offset, bytes, value] of fields) {
    if (bytes === 2) v.setUint16(offset, value, true);
    else v.setUint32(offset, value, true);
  }
  return b;
}

/**
 * ZIP sin datos (las entradas están vacías, solo importa el directorio central).
 * entries: [{name: string | Uint8Array, encrypted?, size?, utf8?}]
 * opts: {eocdTotal?, cdOffset?, cdSize?, comment?: Uint8Array}
 */
export function makeZip(entries, opts = {}) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const name = enc(e.name);
    const flags = (e.encrypted ? 1 : 0) | (e.utf8 === false || e.name instanceof Uint8Array ? 0 : 0x800);
    const local = concat([le(30, [[0, 4, 0x04034b50], [4, 2, 20], [6, 2, flags], [18, 4, e.size ?? 0], [22, 4, e.size ?? 0], [26, 2, name.length]]), name]);
    centrals.push(concat([le(46, [[0, 4, 0x02014b50], [4, 2, 20], [6, 2, 20], [8, 2, flags], [20, 4, e.size ?? 0], [24, 4, e.size ?? 0], [28, 2, name.length], [42, 4, offset]]), name]));
    locals.push(local);
    offset += local.length;
  }
  const cd = concat(centrals);
  const comment = opts.comment ?? new Uint8Array(0);
  const eocd = le(22, [[0, 4, 0x06054b50], [8, 2, opts.eocdTotal ?? entries.length], [10, 2, opts.eocdTotal ?? entries.length],
    [12, 4, opts.cdSize ?? cd.length], [16, 4, opts.cdOffset ?? offset], [20, 2, comment.length]]);
  return concat([...locals, cd, eocd, comment]);
}

const OLE_SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

/**
 * OLE2 (MS-CFB v3, sectores de 512 bytes) con solo la FAT y el directorio.
 * entries: [{name, type: 1 almacenamiento | 2 stream}] — la entrada raíz se añade sola.
 * opts: {selfLoop?: el primer sector del directorio apunta a sí mismo, shift?}
 */
export function makeOle(entries, opts = {}) {
  const all = [{ name: 'Root Entry', type: 5 }, ...entries];
  const dirSectors = Math.ceil(all.length / 4);
  const sectors = 1 + dirSectors;
  const header = new Uint8Array(512);
  const hv = new DataView(header.buffer);
  header.set(OLE_SIG, 0);
  hv.setUint16(24, 0x3e, true);
  hv.setUint16(26, 3, true);
  hv.setUint16(28, 0xfffe, true);
  hv.setUint16(30, opts.shift ?? 9, true);
  hv.setUint16(32, 6, true);
  hv.setUint32(44, 1, true);
  hv.setUint32(48, 1, true);
  hv.setUint32(56, 4096, true);
  hv.setUint32(60, 0xfffffffe, true);
  hv.setUint32(68, 0xfffffffe, true);
  for (let i = 0; i < 109; i++) hv.setUint32(76 + i * 4, i === 0 ? 0 : 0xffffffff, true);

  const body = new Uint8Array(sectors * 512);
  const bv = new DataView(body.buffer);
  for (let i = 0; i < 128; i++) bv.setUint32(i * 4, 0xffffffff, true);
  bv.setUint32(0, 0xfffffffd, true);
  for (let s = 1; s <= dirSectors; s++) bv.setUint32(s * 4, s === dirSectors ? 0xfffffffe : s + 1, true);
  if (opts.selfLoop) bv.setUint32(4, 1, true);
  all.forEach((e, i) => {
    const o = 512 + i * 128;
    const name = String(e.name).slice(0, 31);
    for (let c = 0; c < name.length; c++) bv.setUint16(o + c * 2, name.charCodeAt(c), true);
    bv.setUint16(o + 64, (name.length + 1) * 2, true);
    body[o + 66] = e.type;
    for (const f of [68, 72, 76]) bv.setUint32(o + f, 0xffffffff, true);
    bv.setUint32(o + 116, 0xfffffffe, true);
  });
  return concat([header, body]);
}
