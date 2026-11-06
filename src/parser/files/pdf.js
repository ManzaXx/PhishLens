// PDF: busca nombres que hacen que el visor actúe solo (JavaScript, acciones al abrir,
// lanzar programas, ficheros incrustados). Solo el texto sin comprimir: los flujos
// comprimidos se cuentan para avisar de lo que no se ha mirado. Un único recorrido lineal.
import { latin1 } from './bytes.js';

const TOKENS = ['JavaScript', 'OpenAction', 'Launch', 'EmbeddedFile', 'URI', 'AA'];
const ALIASES = new Map([
  ['JavaScript', 'JavaScript'], ['JS', 'JavaScript'], ['OpenAction', 'OpenAction'], ['Launch', 'Launch'],
  ['EmbeddedFile', 'EmbeddedFile'], ['EmbeddedFiles', 'EmbeddedFile'], ['URI', 'URI'], ['AA', 'AA'],
]);
// Filtros que esconden el contenido (ISO 32000-1 §7.4), con sus abreviaturas.
const FILTERS = new Set(['FlateDecode', 'Fl', 'LZWDecode', 'LZW', 'ASCII85Decode', 'A85', 'ASCIIHexDecode', 'AHx', 'RunLengthDecode', 'RL']);
const NAME_MAX = 64;

// Delimitadores y espacios de ISO 32000-1 §7.2.2.
const ENDS = new Uint8Array(256);
for (const c of '\0\t\n\f\r ()<>[]{}/%') ENDS[c.charCodeAt(0)] = 1;

const hex = (c) => (c >= 48 && c <= 57 ? c - 48 : c >= 65 && c <= 70 ? c - 55 : c >= 97 && c <= 102 ? c - 87 : -1);

/** `{tokens, compressedStreams}`. Nunca lanza. */
export function scanPdf(bytes) {
  const found = new Set();
  let compressedStreams = 0;
  let i = 0;
  while (i < bytes.length) {
    if (bytes[i] !== 0x2f) { i++; continue; }
    i++;
    const name = [];
    while (i < bytes.length && !ENDS[bytes[i]]) {
      let c = bytes[i];
      if (c === 0x23 && i + 2 < bytes.length && hex(bytes[i + 1]) >= 0 && hex(bytes[i + 2]) >= 0) {
        c = hex(bytes[i + 1]) * 16 + hex(bytes[i + 2]);
        i += 2;
      }
      if (name.length < NAME_MAX + 1) name.push(c);
      i++;
    }
    if (!name.length || name.length > NAME_MAX) continue;
    const text = latin1(Uint8Array.from(name));
    const token = ALIASES.get(text);
    if (token) found.add(token);
    else if (FILTERS.has(text)) compressedStreams++;
  }
  return { tokens: TOKENS.filter((t) => found.has(t)), compressedStreams };
}
