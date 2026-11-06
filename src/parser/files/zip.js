// Lista de un ZIP leída solo de su directorio central (APPNOTE 6.3.10 §4.3.12–§4.3.16).
// Nunca se descomprime nada: los datos de cada entrada ni se tocan.
import { reader, startsWith } from './bytes.js';

export const ZIP_MAX_ENTRIES = 1000;
const NAME_MAX = 260;
const EOCD = 'PK\x05\x06';
const CENTRAL = 'PK\x01\x02';
// 22 bytes del EOCD + un comentario de hasta 65.535.
const EOCD_SEARCH = 22 + 0xffff;

// CP437 de 0x80 a 0xFF: lo que usa un ZIP cuando no marca sus nombres como UTF-8.
const CP437 = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';
const utf8 = new TextDecoder('utf-8');

function decodeName(bytes, isUtf8) {
  const slice = bytes.subarray(0, NAME_MAX * 4);
  const text = isUtf8 ? utf8.decode(slice) : Array.from(slice.subarray(0, NAME_MAX), (b) => (b < 0x80 ? String.fromCharCode(b) : CP437[b - 0x80])).join('');
  return [...text].slice(0, NAME_MAX).join('');
}

const fail = (reason) => ({ ok: false, entries: [], truncated: false, reason });

function findEocd(bytes) {
  const stop = Math.max(0, bytes.length - EOCD_SEARCH);
  for (let o = bytes.length - 22; o >= stop; o--) {
    if (bytes[o] === 0x50 && startsWith(bytes, EOCD, o)) return o;
  }
  return -1;
}

/** `{ok, entries: [{name, encrypted, size}], truncated, reason}`. Nunca lanza. */
export function readZip(bytes) {
  const r = reader(bytes);
  const eocd = findEocd(bytes);
  if (eocd < 0) return fail('sin directorio central');
  const total = r.u16(eocd + 10);
  const cdSize = r.u32(eocd + 12);
  const cdOffset = r.u32(eocd + 16);
  // ZIP64 guarda los valores reales en otro registro, justo antes del EOCD.
  if (cdOffset === 0xffffffff || cdSize === 0xffffffff || startsWith(bytes, 'PK\x06\x07', eocd - 20)) return fail('ZIP64 no soportado');
  if (cdOffset + cdSize > eocd) return fail('directorio fuera del fichero');

  const entries = [];
  const end = cdOffset + cdSize;
  let o = cdOffset;
  let truncated = false;
  for (let i = 0; i < total; i++) {
    if (entries.length >= ZIP_MAX_ENTRIES) { truncated = true; break; }
    if (o + 46 > end || !startsWith(bytes, CENTRAL, o)) break;
    const flags = r.u16(o + 8);
    const n = r.u16(o + 28);
    const m = r.u16(o + 30);
    const k = r.u16(o + 32);
    if (o + 46 + n > end) break;
    entries.push({
      name: decodeName(bytes.subarray(o + 46, o + 46 + n), (flags & 0x800) !== 0),
      encrypted: (flags & 1) === 1,
      size: r.u32(o + 24),
    });
    o += 46 + n + m + k;
  }
  return { ok: true, entries, truncated, reason: null };
}
