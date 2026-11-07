// Fuzzing del lote (spec 2.3, §7): con correos mutados, el grafo, su disposición y las campañas
// nunca lanzan, tardan menos de 2 s por lote y no dependen del orden. Semilla fija; más con FUZZ_ITER.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeInput } from '../../src/core/engine.js';
import { emailKey } from '../../src/core/batch.js';
import { buildGraph } from '../../src/intel/graph.js';
import { layoutGraph } from '../../src/intel/layout.js';
import { findCampaigns } from '../../src/intel/campaigns.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { mutate } from './mutate.js';
import { rng, pick } from '../helpers/rng.js';
import { shuffle } from '../helpers/batch.js';
import { toStixBundle } from '../../src/intel/stix.js';
import { validateBundle } from '../../tools/stix-validate.mjs';

const ITER = Math.max(20, Math.round(Number(process.env.FUZZ_ITER ?? 2000) / 20));
const SEED = Number(process.env.FUZZ_SEED ?? 20261107);
const MAX_MS = 2000;

test(`fuzz del lote: ${ITER} lotes de 2 a 20 correos mutados`, () => {
  const r = rng(SEED);
  const texts = Object.values(SAMPLE_TEXTS);
  // Un fondo de correos mutados ya analizados; cada lote toma de ahí.
  const pool = [];
  for (let i = 0; i < 120; i++) {
    let text = texts[pick(r, texts.length)];
    ({ text } = mutate(text, r));
    const key = emailKey(text);
    if (pool.some((e) => e.key === key)) continue;
    pool.push({ key, name: `m${i}.eml`, report: analyzeInput({ kind: 'eml', value: text }) });
  }
  for (let i = 0; i < ITER; i++) {
    const size = 2 + pick(r, 19);
    const lot = new Map();
    while (lot.size < Math.min(size, pool.length)) {
      const e = pool[pick(r, pool.length)];
      lot.set(e.key, e);
    }
    const entries = [...lot.values()];
    const start = performance.now();
    let graph;
    let layout;
    let campaigns;
    try {
      graph = buildGraph(entries);
      layout = layoutGraph(graph);
      campaigns = findCampaigns(entries);
    } catch (err) {
      assert.fail(`lote ${i} (semilla ${SEED}) lanzó: ${err.stack}`);
    }
    const ms = performance.now() - start;
    assert.ok(ms < MAX_MS, `lote ${i}: ${Math.round(ms)} ms`);
    const again = shuffle(entries, i + 1);
    assert.deepEqual(buildGraph(again), graph, `lote ${i}: el grafo depende del orden`);
    assert.deepEqual(layoutGraph(buildGraph(again)), layout, `lote ${i}: la disposición depende del orden`);
    assert.deepEqual(findCampaigns(again), campaigns, `lote ${i}: las campañas dependen del orden`);
    // STIX: todo lote da un bundle válido que sobrevive a JSON.
    const now = new Date(Date.UTC(2026, 10, 7));
    const bundle = toStixBundle(entries, { campaigns, now });
    assert.deepEqual(validateBundle(bundle), [], `lote ${i}: STIX no válido`);
    assert.deepEqual(JSON.parse(JSON.stringify(bundle)), bundle, `lote ${i}: STIX no sobrevive a JSON`);
    assert.deepEqual(toStixBundle(again, { campaigns: findCampaigns(again), now }), bundle, `lote ${i}: STIX depende del orden`);
  }
});
