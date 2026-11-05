// Generador pseudoaleatorio con semilla (mulberry32): los casos "aleatorios" de los tests
// son siempre los mismos y un fallo se puede reproducir con su semilla.
export function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Entero en [0, n). */
export const pick = (r, n) => Math.floor(r() * n);
