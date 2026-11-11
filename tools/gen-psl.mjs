// Genera src/data/psl.js a partir de una copia de la Public Suffix List descargada a mano:
//   curl -o /tmp/psl.dat https://publicsuffix.org/list/public_suffix_list.dat
//   node tools/gen-psl.mjs /tmp/psl.dat
// La web nunca descarga la lista: funciona offline con la copia empaquetada (ADR 0006).
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';

const file = process.argv[2];
if (!file) {
  console.error('Uso: node tools/gen-psl.mjs <public_suffix_list.dat>');
  process.exit(1);
}
const text = readFileSync(file, 'utf8');
const sha256 = createHash('sha256').update(text).digest('hex');

const sections = { icann: [], private: [] };
let section = null;
for (const raw of text.split('\n')) {
  const line = raw.trim();
  if (line.includes('===BEGIN ICANN DOMAINS===')) section = 'icann';
  else if (line.includes('===BEGIN PRIVATE DOMAINS===')) section = 'private';
  if (!line || line.startsWith('//') || !section) continue;
  const rule = line.split(/\s/)[0];
  const prefix = rule.startsWith('!') ? '!' : '';
  const body = prefix ? rule.slice(1) : rule;
  // Cada etiqueta en punycode ("*" se queda como está): así se compara con lo que da new URL().
  const ascii = body.split('.').map((l) => (l === '*' ? l : domainToASCII(l) || l.toLowerCase())).join('.');
  sections[section].push(prefix + ascii);
}
const total = sections.icann.length + sections.private.length;
const date = process.argv[3] ?? new Date().toISOString().slice(0, 10);

const out = `// GENERADO por tools/gen-psl.mjs: no editar a mano.
// Public Suffix List (https://publicsuffix.org/), copia del ${date}.
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Reglas en punycode, una por línea; "!" = excepción, "*." = comodín.

export const PSL_META = Object.freeze({ date: '${date}', sha256: '${sha256}', rules: ${total} });

export const PSL_ICANN = ${JSON.stringify(sections.icann.join('\n'))};

export const PSL_PRIVATE = ${JSON.stringify(sections.private.join('\n'))};
`;
writeFileSync(new URL('../src/data/psl.js', import.meta.url), out);
console.log(`src/data/psl.js: ${sections.icann.length} reglas ICANN + ${sections.private.length} privadas (${Math.round(out.length / 1024)} KB)`);
