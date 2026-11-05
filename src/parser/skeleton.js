// "Esqueleto" visual de un texto (Unicode UTS #39): cada carácter que se confunde con una letra
// o cifra ASCII se sustituye por ella, para comparar dominios por cómo se VEN y no por sus bytes.
import { CONFUSABLES } from '../data/confusables.js';

const MAX_LENGTH = 253;

/** NFKC, sustitución de confusables y minúsculas. */
export function skeleton(text) {
  let out = '';
  for (const ch of String(text ?? '').slice(0, MAX_LENGTH).normalize('NFKC')) {
    out += CONFUSABLES.get(ch.codePointAt(0)) ?? ch;
  }
  return out.toLowerCase();
}

// Ambigüedades que ya existen dentro de ASCII y que UTS #39 resuelve de otra forma según la
// versión (en Unicode 16 la palochka "ӏ" es "i", pero en pantalla se lee como "l").
const fold = (s) => s.replace(/[il1|]/g, 'l').replace(/0/g, 'o').replace(/rn/g, 'm').replace(/vv/g, 'w');

/** ¿Se ven igual? Compara los esqueletos de los dos textos. */
export function sameShape(a, b) {
  return fold(skeleton(a)) === fold(skeleton(b));
}

/** Letras de un texto que imitan a una ASCII: "⟦U+0430 а→a⟧". */
export function foreignLookalikes(text) {
  const out = [];
  for (const ch of new Set(String(text ?? '').slice(0, MAX_LENGTH))) {
    const ascii = CONFUSABLES.get(ch.codePointAt(0));
    if (ascii) out.push(`⟦U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')} ${ch}→${ascii}⟧`);
  }
  return out;
}

const SCRIPTS = [
  ['Latin', /\p{Script=Latin}/u],
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Armenian', /\p{Script=Armenian}/u],
];
const COMMON = /[\p{Script=Common}\p{Script=Inherited}]/u;

/** Alfabetos que aparecen en una etiqueta; cifras, guiones y signos no cuentan. */
export function scriptsOf(label) {
  const found = new Set();
  for (const ch of String(label ?? '').slice(0, MAX_LENGTH)) {
    if (COMMON.test(ch)) continue;
    found.add(SCRIPTS.find(([, re]) => re.test(ch))?.[0] ?? 'Other');
  }
  return found;
}
