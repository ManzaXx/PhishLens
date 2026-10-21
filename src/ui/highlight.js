// Divide el texto del email en trozos para resaltar frases sospechosas y URLs sin usar innerHTML.
import { LANGUAGE_PATTERNS } from '../data/lists.js';

const MAX_CHARS = 20000;
const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;
const PHRASE_RES = Object.values(LANGUAGE_PATTERNS)
  .flatMap((rule) => rule.patterns)
  .map((re) => new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`));

/** Devuelve [{text, kind: 'phrase' | 'url' | null}] que, unidos, reproducen el texto. */
export function highlight(input) {
  const text = input.length > MAX_CHARS ? `${input.slice(0, MAX_CHARS)}…` : input;
  const ranges = [];
  for (const re of PHRASE_RES) {
    for (const m of text.matchAll(re)) ranges.push([m.index, m.index + m[0].length, 'phrase']);
  }
  for (const m of text.matchAll(URL_RE)) {
    let end = m.index + m[0].length;
    while (end > m.index && /[.,;:!?)]/.test(text[end - 1])) end--;
    ranges.push([m.index, end, 'url']);
  }
  ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);

  const parts = [];
  let pos = 0;
  for (const [start, end, kind] of ranges) {
    if (start < pos) continue; // solapado con el anterior
    if (start > pos) parts.push({ text: text.slice(pos, start), kind: null });
    parts.push({ text: text.slice(start, end), kind });
    pos = end;
  }
  if (pos < text.length || parts.length === 0) parts.push({ text: text.slice(pos), kind: null });
  return parts;
}
