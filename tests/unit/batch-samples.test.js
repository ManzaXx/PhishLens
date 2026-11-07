import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { BATCHES, SAMPLES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeBatch } from '../../src/core/batch.js';
import { findCampaigns } from '../../src/intel/campaigns.js';
import { buildBatchGolden, BATCH_GOLDEN_PATH } from '../helpers/golden.js';

const asFile = (name, text) => ({ name, size: text.length, text: async () => text });
const batchFiles = (b) => b.files.map((f) => asFile(f.split('/').pop(), SAMPLE_TEXTS[f]));
const noYield = { yieldFn: async () => {} };

test('hay un lote de ejemplo de 4 correos, ninguno legítimo', async () => {
  assert.deepEqual(BATCHES.map((b) => [b.id, b.title, b.files.length]), [['lote-campana', 'Lote de campaña (4 correos)', 4]]);
  const { entries, skipped } = await analyzeBatch(batchFiles(BATCHES[0]), noYield);
  assert.equal(entries.length, 4);
  assert.deepEqual(skipped, []);
  for (const e of entries) assert.notEqual(e.report.level, 'safe', e.name);
});

test('el lote forma una campaña de 4 con pistas de los tres tipos y la marca Correos', async () => {
  const { entries } = await analyzeBatch(batchFiles(BATCHES[0]), noYield);
  const campaigns = findCampaigns(entries);
  assert.equal(campaigns.length, 1);
  assert.equal(campaigns[0].emails.length, 4);
  assert.deepEqual([...new Set(campaigns[0].reasons.map((r) => r.kind))].sort(), ['hash', 'infra', 'kit']);
  assert.deepEqual(campaigns[0].brands, ['Correos']);
});

test('el lote junto con las 12 muestras: la campaña sigue siendo de 4 y las legítimas no entran', async () => {
  const files = [...batchFiles(BATCHES[0]), ...SAMPLES.map((s) => asFile(s.file, SAMPLE_TEXTS[s.id]))];
  const { entries } = await analyzeBatch(files, noYield);
  const campaigns = findCampaigns(entries);
  const byName = new Map(entries.map((e) => [e.key, e.name]));
  const lot = campaigns.find((c) => c.emails.some((k) => byName.get(k).startsWith('1-')));
  assert.equal(lot.emails.length, 4);
  const inCampaign = new Set(campaigns.flatMap((c) => c.emails.map((k) => byName.get(k))));
  for (const legit of ['01-legitimo-newsletter.eml', '02-legitimo-pedido.eml']) assert.ok(!inCampaign.has(legit), legit);
});

test('grafo y campañas del lote no cambian (golden)', async () => {
  assert.deepEqual(await buildBatchGolden(), JSON.parse(readFileSync(BATCH_GOLDEN_PATH, 'utf8')));
});

test('samples/data.js incluye los correos del lote tal cual', () => {
  for (const f of BATCHES[0].files) {
    assert.equal(SAMPLE_TEXTS[f], readFileSync(new URL(`../../samples/${f}`, import.meta.url), 'utf8'), f);
  }
});
