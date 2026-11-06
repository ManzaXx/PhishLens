// PDF: busca nombres que hacen que el visor actúe solo (JavaScript, acciones al abrir,
// lanzar programas, ficheros incrustados). Solo el texto sin comprimir: los flujos
// comprimidos se cuentan para avisar de lo que no se ha mirado. Un único recorrido lineal
// que no crea nada por nombre salvo que pueda ser uno de los buscados.

const TOKENS = ['JavaScript', 'OpenAction', 'Launch', 'EmbeddedFile', 'URI', 'AA'];
const ALIASES = new Map([
  ['JavaScript', 'JavaScript'], ['JS', 'JavaScript'], ['OpenAction', 'OpenAction'], ['Launch', 'Launch'],
  ['EmbeddedFile', 'EmbeddedFile'], ['EmbeddedFiles', 'EmbeddedFile'], ['URI', 'URI'], ['AA', 'AA'],
]);
// Filtros que esconden el contenido (ISO 32000-1 §7.4), con sus abreviaturas.
const FILTERS = new Set(['FlateDecode', 'Fl', 'LZWDecode', 'LZW', 'ASCII85Decode', 'A85', 'ASCIIHexDecode', 'AHx', 'RunLengthDecode', 'RL']);
// Ningún nombre buscado pasa de 15 caracteres: lo más largo se descarta sin guardarlo.
const NAME_MAX = 15;

// Delimitadores y espacios de ISO 32000-1 §7.2.2.
const ENDS = new Uint8Array(256);
for (const c of '\0\t\n\f\r ()<>[]{}/%') ENDS[c.charCodeAt(0)] = 1;

const hex = (c) => (c >= 48 && c <= 57 ? c - 48 : c >= 65 && c <= 70 ? c - 55 : c >= 97 && c <= 102 ? c - 87 : -1);

/** `{tokens, compressedStreams}`. Nunca lanza. */
export function scanPdf(bytes) {
  const found = new Set();
  let compressedStreams = 0;
  const len = bytes.length;
  let i = 0;
  while (i < len) {
    if (bytes[i] !== 0x2f) { i++; continue; }
    i++;
    let name = '';
    let n = 0;
    while (i < len && !ENDS[bytes[i]]) {
      let c = bytes[i];
      if (c === 0x23 && i + 2 < len) {
        const h = hex(bytes[i + 1]);
        const l = hex(bytes[i + 2]);
        if (h >= 0 && l >= 0) { c = h * 16 + l; i += 2; }
      }
      if (++n <= NAME_MAX) name += String.fromCharCode(c);
      i++;
    }
    if (!n || n > NAME_MAX) continue;
    const token = ALIASES.get(name);
    if (token) found.add(token);
    else if (FILTERS.has(name)) compressedStreams++;
  }
  return { tokens: TOKENS.filter((t) => found.has(t)), compressedStreams };
}
