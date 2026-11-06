// Utilidades de texto compartidas por el motor y la interfaz.

// Caracteres de control bidireccional e invisibles (ver "Trojan Source", CVE-2021-42574).
export const INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/** Sustituye los caracteres invisibles por una marca visible, p. ej. ⟦U+202E⟧. */
export function reveal(text) {
  return String(text).replace(INVISIBLE_RE, (c) => `⟦U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}⟧`);
}

/** Lectura segura de diccionarios: ignora propiedades heredadas como "constructor". */
export function own(obj, key) {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}
