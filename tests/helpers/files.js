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
