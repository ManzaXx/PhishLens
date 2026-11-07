// Huella del "kit" de un correo: asunto normalizado + plantilla del cuerpo en shingles de 3 palabras.
// Dos correos del mismo kit cambian nombres, importes y enlaces, pero no el texto de la plantilla.

export const KIT_THRESHOLD = 0.6;
const MAX_CHARS = 20000;
const MAX_SHINGLES = 5000;
const MIN_WORDS = 10;
const SHINGLE = 3;

/** FNV-1a de 32 bits. */
function fnv(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

const stripReplies = (subject) => String(subject ?? '').replace(/^\s*((re|fwd?|rv|fw)\s*:\s*)+/i, '');

/** Texto del cuerpo: el texto plano o, si no hay, el HTML sin etiquetas. */
const bodyOf = (email) => (email?.text?.trim() ? email.text : String(email?.html ?? '').replace(/<[^>]*>/g, ' '));

/** @returns {{shingles: Set<number>, words: number}} */
export function kitOf(report) {
  const email = report?.email ?? {};
  const raw = `${stripReplies(email.subject)} ${bodyOf(email)}`.slice(0, MAX_CHARS);
  const words = raw.normalize('NFKC').toLowerCase()
    .replace(/(https?:\/\/|www\.)\S+/g, ' url ')
    .replace(/\d/g, '0')
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean);
  const shingles = new Set();
  for (let i = 0; i + SHINGLE <= words.length && shingles.size < MAX_SHINGLES; i++) {
    shingles.add(fnv(words.slice(i, i + SHINGLE).join(' ')));
  }
  return { shingles, words: words.length };
}

/** Similitud de Jaccard entre dos kits; 0 si alguno es demasiado corto para compararlo. */
export function similarity(a, b) {
  if (a.words < MIN_WORDS || b.words < MIN_WORDS || !a.shingles.size || !b.shingles.size) return 0;
  const [small, large] = a.shingles.size <= b.shingles.size ? [a.shingles, b.shingles] : [b.shingles, a.shingles];
  let common = 0;
  for (const s of small) if (large.has(s)) common++;
  return common / (a.shingles.size + b.shingles.size - common);
}
