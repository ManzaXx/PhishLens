// Lector acotado sobre un Uint8Array: cualquier lectura fuera de [0, length) devuelve null
// en vez de lanzar o leer basura. Todos los lectores de formatos se apoyan en él.

const valid = (o, n, length) => Number.isInteger(o) && Number.isInteger(n) && o >= 0 && n >= 0 && o + n <= length;

/** Lector little-endian de `bytes`. */
export function reader(bytes) {
  const length = bytes.length;
  return {
    length,
    u8: (o) => (valid(o, 1, length) ? bytes[o] : null),
    u16: (o) => (valid(o, 2, length) ? bytes[o] | (bytes[o + 1] << 8) : null),
    u32: (o) => (valid(o, 4, length) ? (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0 : null),
    ascii: (o, n) => (valid(o, n, length) ? latin1(bytes, o, n) : null),
    latin1: (o, n) => (valid(o, n, length) ? latin1(bytes, o, n) : null),
  };
}

/** Bytes como texto Latin-1 (un carácter por byte), por trozos para no llenar la pila. */
export function latin1(bytes, start = 0, n = bytes.length - start) {
  let out = '';
  for (let i = start; i < start + n; i += 8192) out += String.fromCharCode(...bytes.subarray(i, Math.min(i + 8192, start + n)));
  return out;
}

/** ¿Empiezan los bytes en `offset` por `sig` (cadena Latin-1 o lista de bytes)? */
export function startsWith(bytes, sig, offset = 0) {
  if (offset < 0 || offset + sig.length > bytes.length) return false;
  for (let i = 0; i < sig.length; i++) {
    const want = typeof sig === 'string' ? sig.charCodeAt(i) : sig[i];
    if (bytes[offset + i] !== want) return false;
  }
  return true;
}
