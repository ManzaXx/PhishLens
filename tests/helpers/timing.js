// Medidas de tiempo para tests que no dependan de la suerte del runner.
//
// `node --test` ejecuta los ficheros en paralelo y los runners de CI son compartidos: una sola medida puede salir
// lenta por un GC, por el JIT o por otro proceso. Un fallo de rendimiento de verdad (un bucle cuadrático, un ReDoS)
// es lento SIEMPRE con la misma entrada, así que repetir la misma entrada no lo esconde: solo filtra el ruido.
//
// - withinBudget: repite hasta `attempts` veces y se queda con la mejor; falla solo si todas pasan del presupuesto.
// - assertScales: compara el tiempo con una entrada n y con otra `factor` veces mayor. Un algoritmo lineal crece
//   ~factor; uno cuadrático, ~factor². Detecta la regresión aunque el runner sea rápido o lento en términos absolutos.
import assert from 'node:assert/strict';

const now = () => performance.now();

/** Ejecuta `fn` una vez y devuelve { ms, value }. */
export function timeOnce(fn) {
  const t0 = now();
  const value = fn();
  return { ms: now() - t0, value };
}

/**
 * Repite `fn` hasta que una vuelta quede dentro de `budgetMs` o se agoten los intentos.
 * @returns {{ best: number, runs: number[], value: unknown, ok: boolean }}
 */
export function withinBudget(fn, budgetMs, { attempts = 3 } = {}) {
  const runs = [];
  let value;
  for (let i = 0; i < attempts; i++) {
    const r = timeOnce(fn);
    runs.push(r.ms);
    value = r.value;
    if (r.ms < budgetMs) break;
  }
  const best = Math.min(...runs);
  return { best, runs, value, ok: best < budgetMs };
}

const fmt = (runs) => runs.map((ms) => `${ms.toFixed(1)} ms`).join(', ');

/** Como withinBudget, pero falla con todas las medidas en el mensaje. Devuelve lo que devolvió `fn`. */
export function assertWithinBudget(fn, budgetMs, label = 'operación', opts) {
  const r = withinBudget(fn, budgetMs, opts);
  assert.ok(r.ok, `${label}: más de ${budgetMs} ms en todos los intentos (${fmt(r.runs)})`);
  return r.value;
}

/** Versión asíncrona de assertWithinBudget. */
export async function assertWithinBudgetAsync(fn, budgetMs, label = 'operación', { attempts = 3 } = {}) {
  const runs = [];
  let value;
  for (let i = 0; i < attempts; i++) {
    const t0 = now();
    value = await fn();
    runs.push(now() - t0);
    if (runs.at(-1) < budgetMs) break;
  }
  assert.ok(Math.min(...runs) < budgetMs, `${label}: más de ${budgetMs} ms en todos los intentos (${fmt(runs)})`);
  return value;
}

/** Mejor de `repeat` vueltas (tras una de calentamiento si `warmup`). */
export function bestOf(fn, { repeat = 3, warmup = true } = {}) {
  if (warmup) fn();
  let best = Infinity;
  for (let i = 0; i < repeat; i++) best = Math.min(best, timeOnce(fn).ms);
  return best;
}

/**
 * Comprueba que `run(make(n))` crece casi lineal. Mide n y factor·n (mejor de `repeat`) y exige
 * grande/pequeño ≤ maxRatio. Con factor 8 lo lineal da ~8 y lo cuadrático ~64; el margen por defecto (×3)
 * absorbe el ruido sin dejar pasar lo cuadrático. Si la entrada grande tarda menos de `floorMs` no hay nada
 * que medir con precisión y se acepta (el presupuesto absoluto del test sigue vigilando ese caso).
 * @returns {{ small: number, large: number, ratio: number }}
 */
export function measureScaling(make, run, { n, factor = 8, repeat = 3 } = {}) {
  const smallInput = make(n);
  const largeInput = make(n * factor);
  const small = bestOf(() => run(smallInput), { repeat });
  const large = bestOf(() => run(largeInput), { repeat });
  return { small, large, ratio: large / Math.max(small, 0.01) };
}

export function assertScales(make, run, { n, factor = 8, maxRatio = factor * 3, floorMs = 5, label = 'operación', repeat = 3 } = {}) {
  let m = measureScaling(make, run, { n, factor, repeat });
  // Un segundo intento por si una de las dos medidas cayó en una pausa del runner.
  if (m.ratio > maxRatio && m.large >= floorMs) m = measureScaling(make, run, { n, factor, repeat });
  if (process.env.TIMING_LOG) console.error(`[timing] ${label}: ${m.small.toFixed(2)} → ${m.large.toFixed(2)} ms (×${m.ratio.toFixed(1)})`);
  assert.ok(m.ratio <= maxRatio || m.large < floorMs,
    `${label}: con ${factor}× más entrada tarda ${m.ratio.toFixed(1)}× más (${m.small.toFixed(2)} → ${m.large.toFixed(2)} ms); `
    + `lo lineal rondaría ${factor}×, el límite es ${maxRatio}×`);
  return m;
}

/** Percentiles de una lista de tiempos, para los diagnósticos del fuzzing. */
export function percentiles(times) {
  if (!times.length) return { p50: 0, p99: 0, max: 0 };
  const s = Float64Array.from(times).sort();
  const at = (q) => s[Math.min(s.length - 1, Math.floor(q * s.length))];
  return { p50: at(0.5), p99: at(0.99), max: s[s.length - 1] };
}
