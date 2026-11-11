// Fuzzing con semilla fija (spec 2.2, §8.2). Más casos en local: FUZZ_ITER=20000 npm run fuzz
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SAMPLES } from '../../samples/index.js';
import { parseEml } from '../../src/parser/eml.js';
import { analyzeInput } from '../../src/core/engine.js';
import { rng, pick } from '../helpers/rng.js';
import { withinBudget, percentiles } from '../helpers/timing.js';
import { mutate, MUTATION_NAMES } from './mutate.js';

const ITER = Number(process.env.FUZZ_ITER ?? 2000);
const SEED = Number(process.env.FUZZ_SEED ?? 20261105);
const MAX_MS = 2000;
const texts = SAMPLES.map((s) => readFileSync(new URL(`../../samples/${s.file}`, import.meta.url), 'utf8'));

test('cada mutación cambia algo en alguna muestra', () => {
  const r = rng(1);
  for (const name of MUTATION_NAMES) assert.ok(name);
  assert.ok(texts.some((t) => mutate(t, r).text !== t));
});

test(`fuzzing: ${ITER} correos mutados no rompen el parser ni el motor`, (t) => {
  const r = rng(SEED);
  const times = [];
  for (let i = 0; i < ITER; i++) {
    const base = pick(r, texts.length);
    const { text, applied } = mutate(texts[base], r);
    const where = `caso ${i} (semilla ${SEED}, muestra ${SAMPLES[base].id}, mutaciones ${applied.join('+')})`;
    let report;
    let timing;
    try {
      timing = withinBudget(() => {
        parseEml(text);
        return analyzeInput({ kind: 'eml', value: text });
      }, MAX_MS);
    } catch (err) {
      assert.fail(`${where}: lanzó ${err?.stack ?? err}`);
    }
    report = timing.value;
    times.push(timing.runs[0]);
    assert.ok(timing.ok, `${where}: más de ${MAX_MS} ms en todos los intentos (${timing.runs.map((ms) => Math.round(ms)).join(', ')} ms)`);
    assert.ok(report.score >= 0 && report.score <= 100, `${where}: nota ${report.score}`);
    assert.deepEqual(report.errors, [], `${where}: detector caído ${JSON.stringify(report.errors)}`);
  }
  const p = percentiles(times);
  t.diagnostic(`parseEml + analyzeInput: p50 ${p.p50.toFixed(2)} ms · p99 ${p.p99.toFixed(2)} ms · máx ${p.max.toFixed(2)} ms (primer intento)`);
});
