// Recorre un mensaje en bloques de 64 bytes con el relleno de MD5/SHA-1/SHA-2
// (0x80, ceros y la longitud en bits en 64 bits) sin copiar el mensaje entero.
// `littleEndian` elige el orden de la longitud: true en MD5, false en SHA.

/** Llama a `fn(view, offset)` por cada bloque de 64 bytes. */
export function eachBlock(bytes, littleEndian, fn) {
  const length = bytes.length;
  const full = length - (length % 64);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let offset = 0; offset < full; offset += 64) fn(view, offset);

  const tail = new Uint8Array(length % 64 < 56 ? 64 : 128);
  tail.set(bytes.subarray(full));
  tail[length - full] = 0x80;
  const tv = new DataView(tail.buffer);
  const hi = Math.floor(length / 0x20000000);
  const lo = (length * 8) >>> 0;
  if (littleEndian) {
    tv.setUint32(tail.length - 8, lo, true);
    tv.setUint32(tail.length - 4, hi, true);
  } else {
    tv.setUint32(tail.length - 8, hi);
    tv.setUint32(tail.length - 4, lo);
  }
  for (let offset = 0; offset < tail.length; offset += 64) fn(tv, offset);
}
