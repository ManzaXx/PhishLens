// MD5 síncrono en JavaScript puro (RFC 1321). Solo para identificar adjuntos como IOC:
// MD5 está roto para firmar, pero es el hash que aún usan muchos feeds y antivirus.
import { eachBlock } from './blocks.js';

const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
// K[i] = floor(|sin(i + 1)| · 2^32), RFC 1321 §3.4.
const K = Uint32Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32));

const rotl = (x, n) => (x << n) | (x >>> (32 - n));

/** Hash MD5 de unos bytes, en hexadecimal (32 caracteres). */
export function md5(bytes) {
  const h = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);
  const m = new Uint32Array(16);
  eachBlock(bytes, true, (view, offset) => {
    for (let i = 0; i < 16; i++) m[i] = view.getUint32(offset + i * 4, true);
    let [a, b, c, d] = h;
    for (let i = 0; i < 64; i++) {
      let f;
      let g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const t = d;
      d = c;
      c = b;
      b = (b + rotl((a + f + K[i] + m[g]) >>> 0, S[(i >> 4) * 4 + (i % 4)])) >>> 0;
      a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  });
  return [...h].map((x) => [0, 8, 16, 24].map((s) => ((x >>> s) & 0xff).toString(16).padStart(2, '0')).join('')).join('');
}
