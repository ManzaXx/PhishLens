// Mutaciones para el fuzzing: cada una imita una forma real de romper un .eml.
import { pick } from '../helpers/rng.js';

const MUTATIONS = {
  randomBytes(text, r) {
    const chars = [...text.slice(0, 200000)];
    for (let i = 0; i < 1 + pick(r, 20); i++) chars[pick(r, chars.length || 1)] = String.fromCharCode(pick(r, 0x10000));
    return chars.join('') + text.slice(200000);
  },
  cut(text, r) {
    const a = pick(r, text.length + 1);
    return text.slice(0, a) + text.slice(a + pick(r, 2000));
  },
  duplicateHeader(text, r) {
    const lines = text.split(/\r?\n/);
    const end = lines.indexOf('');
    if (end <= 0) return text;
    const i = pick(r, end);
    lines.splice(i, 0, lines[i], lines[i]);
    return lines.join('\r\n');
  },
  breakBoundary(text) {
    return text.replace(/boundary="?([^";\r\n]+)"?/i, (m, b) => `boundary="${b}"; boundary="${b}x"`).replace(/--([^\s-]{4,})--/, '--$1');
  },
  deepNesting(text) {
    let open = '';
    let close = '';
    for (let i = 0; i < 30; i++) {
      open += `Content-Type: multipart/mixed; boundary="n${i}"\r\n\r\n--n${i}\r\n`;
      close = `\r\n--n${i}--${close}`;
    }
    return text.replace(/\r?\n\r?\n/, `\r\n${open}\r\n`) + close;
  },
  hugeLine(text, r) {
    const at = pick(r, text.length + 1);
    return `${text.slice(0, at)}${'A'.repeat(1024 * 1024)}${text.slice(at)}`;
  },
  badEncodedWord(text) {
    return text.replace(/^Subject:.*$/m, 'Subject: =?UTF-8?B?////?= =?x?Q?=ZZ=?= =?UTF-8?B?');
  },
  cutQuotedPrintable(text) {
    return text.replace(/=\r?\n/, '=').replace(/=[0-9A-F]{2}/, '=Z');
  },
  nulAndSurrogates(text, r) {
    const at = pick(r, text.length + 1);
    return `${text.slice(0, at)}\u0000𐏿\udc00${text.slice(at)}`;
  },
  bareCr(text) {
    return text.replace(/\r?\n/g, '\r');
  },
};

export const MUTATION_NAMES = Object.keys(MUTATIONS);

/** Aplica de 1 a 3 mutaciones al azar. Devuelve el texto y los nombres aplicados. */
export function mutate(text, r) {
  const applied = [];
  let out = text;
  for (let i = 0; i < 1 + pick(r, 3); i++) {
    const name = MUTATION_NAMES[pick(r, MUTATION_NAMES.length)];
    out = MUTATIONS[name](out, r);
    applied.push(name);
  }
  return { text: out, applied };
}
