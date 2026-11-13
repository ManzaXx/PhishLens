// La ayuda de tiempos tiene que distinguir lo lineal de lo cuadrático y no fallar por una vuelta lenta suelta.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withinBudget, assertWithinBudget, assertScales, measureScaling, percentiles } from '../helpers/timing.js';

const linear = (s) => {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
};
// El mismo trabajo, pero volviendo a recorrer lo ya visto: el error típico de un parser que reescanea.
const quadratic = (s) => {
  let h = 0;
  for (let i = 0; i < s.length; i++) for (let j = 0; j < i; j += 1) h = (h + s.charCodeAt(j)) | 0;
  return h;
};
const make = (n) => 'a'.repeat(n);

test('assertScales acepta un algoritmo lineal', () => {
  const m = assertScales(make, linear, { n: 200_000, label: 'lineal' });
  assert.ok(m.ratio < 24, `ratio ${m.ratio}`);
});

test('assertScales detecta un algoritmo cuadrático aunque sea rápido en términos absolutos', () => {
  const m = measureScaling(make, quadratic, { n: 1000 });
  assert.ok(m.ratio > 24, `ratio ${m.ratio.toFixed(1)}`);
  assert.throws(() => assertScales(make, quadratic, { n: 1000, label: 'cuadrático' }), /cuadrático: con 8× más entrada/);
});

test('withinBudget no falla por una sola vuelta lenta, pero sí si todas lo son', () => {
  let calls = 0;
  const flaky = () => {
    calls++;
    if (calls === 1) { const end = performance.now() + 30; while (performance.now() < end); }
    return 'ok';
  };
  const r = withinBudget(flaky, 20);
  assert.equal(r.ok, true);
  assert.equal(r.runs.length, 2);
  assert.equal(r.value, 'ok');

  const slow = () => { const end = performance.now() + 25; while (performance.now() < end); };
  assert.throws(() => assertWithinBudget(slow, 20, 'lento'), /lento: más de 20 ms en todos los intentos/);
});

test('percentiles de una lista de tiempos', () => {
  const p = percentiles(Array.from({ length: 100 }, (_, i) => i + 1));
  assert.deepEqual(p, { p50: 51, p99: 100, max: 100 });
  assert.deepEqual(percentiles([]), { p50: 0, p99: 0, max: 0 });
});
