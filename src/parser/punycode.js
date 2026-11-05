// Decodificador Punycode (RFC 3492) propio: convierte "xn--80ak6aa92e" en "аррӏе" para poder
// enseñar al usuario las letras reales de un dominio internacional y compararlas con marcas.

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_INT = 0x7fffffff;
const MAX_LABEL = 63;
const MAX_DOMAIN = 253;

function digitOf(code) {
  if (code >= 48 && code <= 57) return code - 22; // 0-9 → 26-35
  if (code >= 65 && code <= 90) return code - 65; // A-Z
  if (code >= 97 && code <= 122) return code - 97; // a-z
  return BASE;
}

function adapt(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

/** Decodifica la parte que va tras "xn--". Devuelve null si no es Punycode válido. */
export function decodeLabel(input) {
  const text = String(input ?? '');
  if (!text || text.length > MAX_LABEL || !/^[\x20-\x7e]+$/.test(text)) return null;
  const delimiter = text.lastIndexOf('-');
  const output = delimiter > 0 ? [...text.slice(0, delimiter)].map((c) => c.codePointAt(0)) : [];
  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let i = 0;
  for (let pos = delimiter > 0 ? delimiter + 1 : 0; pos < text.length;) {
    const oldI = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= text.length) return null;
      const digit = digitOf(text.charCodeAt(pos++));
      if (digit >= BASE || digit > Math.floor((MAX_INT - i) / w)) return null;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) return null;
      w *= BASE - t;
    }
    const length = output.length + 1;
    bias = adapt(i - oldI, length, oldI === 0);
    if (Math.floor(i / length) > MAX_INT - n) return null;
    n += Math.floor(i / length);
    i %= length;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
    output.splice(i, 0, n);
    i++;
  }
  return output.length ? String.fromCodePoint(...output) : null;
}

/** Dominio con cada etiqueta "xn--" en Unicode; las inválidas se dejan como están. */
export function toUnicode(domain) {
  const text = String(domain ?? '');
  if (text.length > MAX_DOMAIN) return text;
  // Los dominios no distinguen mayúsculas; Punycode conserva las de la parte ASCII.
  return text.toLowerCase().split('.').map((label) => {
    if (!/^xn--/i.test(label)) return label;
    return decodeLabel(label.slice(4)) ?? label;
  }).join('.');
}
