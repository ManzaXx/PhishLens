// SHA-1 síncrono en JavaScript puro (FIPS 180-4 §6.1). Solo para identificar adjuntos
// como IOC: SHA-1 ya no sirve para firmar, pero sigue siendo el hash que piden muchos feeds.
import { eachBlock } from './blocks.js';

const rotl = (x, n) => (x << n) | (x >>> (32 - n));

/** Hash SHA-1 de unos bytes, en hexadecimal (40 caracteres). */
export function sha1(bytes) {
  const h = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
  const w = new Uint32Array(80);
  eachBlock(bytes, false, (view, offset) => {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    let [a, b, c, d, e] = h;
    for (let i = 0; i < 80; i++) {
      let f;
      let k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const t = (rotl(a, 5) + f + e + k + w[i]) >>> 0;
      e = d; d = c; c = rotl(b, 30) >>> 0; b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
  });
  return [...h].map((x) => x.toString(16).padStart(8, '0')).join('');
}
