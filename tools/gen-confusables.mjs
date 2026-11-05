// Genera src/data/confusables.js a partir de confusables.txt de Unicode (UTS #39).
// Herramienta de desarrollo: se ejecuta a mano y su salida se commitea; nunca en CI ni en el navegador.
//
//   curl -o confusables.txt https://raw.githubusercontent.com/unicode-org/unicodetools/main/unicodetools/data/security/16.0.0/confusables.txt
//   node tools/gen-confusables.mjs confusables.txt
//
// Solo se guardan los caracteres NO ASCII cuyo destino es una única letra o cifra ASCII.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const SOURCE_URL = 'https://raw.githubusercontent.com/unicode-org/unicodetools/main/unicodetools/data/security/16.0.0/confusables.txt';
const path = process.argv[2];
if (!path) throw new Error('Uso: node tools/gen-confusables.mjs confusables.txt');
const text = readFileSync(path, 'utf8');
const version = /^# Version: (.+)$/m.exec(text)?.[1]?.trim();
const date = /^# Date: (.+)$/m.exec(text)?.[1]?.trim();
const sha256 = createHash('sha256').update(text).digest('hex');

const pairs = [];
for (const line of text.split('\n')) {
  const m = /^([0-9A-F]{4,6})\s*;\s*([0-9A-F ]+?)\s*;/.exec(line);
  if (!m || m[2].includes(' ')) continue;
  const source = parseInt(m[1], 16);
  const target = String.fromCodePoint(parseInt(m[2], 16));
  if (source < 0x80 || !/^[A-Za-z0-9]$/.test(target)) continue;
  pairs.push([source, target.toLowerCase()]);
}
pairs.sort((a, b) => a[0] - b[0]);

const body = pairs.map(([cp, t]) => `0x${cp.toString(16)},'${t}'`).join(',');
writeFileSync(new URL('../src/data/confusables.js', import.meta.url), `// Caracteres que se confunden con letras y cifras ASCII, de Unicode UTS #39.
// GENERADO por tools/gen-confusables.mjs: no editar a mano.
// Fuente: ${SOURCE_URL}
// Versión ${version} · ${date} · sha256 ${sha256}
// © Unicode, Inc. Términos de uso: https://www.unicode.org/terms_of_use.html
// ${pairs.length} entradas: [punto de código, letra ASCII en minúscula, …]
const FLAT = [${body}];

/** Mapa punto de código → letra o cifra ASCII. */
export const CONFUSABLES = new Map();
for (let i = 0; i < FLAT.length; i += 2) CONFUSABLES.set(FLAT[i], FLAT[i + 1]);

export const CONFUSABLES_VERSION = '${version}';
`);
console.log(`${pairs.length} entradas, Unicode ${version}`);
