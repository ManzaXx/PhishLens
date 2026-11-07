// Foto "golden" de los informes de las muestras. Desde el PR 4 incluye la nota contextual
// (categorías, confianza, correlaciones) y el modelo nuevo de cada hallazgo.
// Uso: node tests/helpers/golden.js --write
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SAMPLES, BATCHES } from '../../samples/index.js';
import { analyzeBatch } from '../../src/core/batch.js';
import { buildGraph } from '../../src/intel/graph.js';
import { findCampaigns } from '../../src/intel/campaigns.js';
import { analyzeInput } from '../../src/core/engine.js';

export const GOLDEN_PATH = new URL('../unit/__golden__/samples.json', import.meta.url);
export const BATCH_GOLDEN_PATH = new URL('../unit/__golden__/lote-campana.json', import.meta.url);

/** Grafo y campañas del lote de ejemplo. */
export async function buildBatchGolden() {
  const files = BATCHES[0].files.map((f) => {
    const text = readFileSync(new URL(`../../samples/${f}`, import.meta.url), 'utf8');
    return { name: f.split('/').pop(), size: text.length, text: async () => text };
  });
  const { entries } = await analyzeBatch(files, { yieldFn: async () => {} });
  return JSON.parse(JSON.stringify({ graph: buildGraph(entries), campaigns: findCampaigns(entries) }));
}

const pick = (obj, keys) => Object.fromEntries(keys.map((k) => [k, obj?.[k] ?? null]));

export function legacyView(report) {
  const { email } = report;
  return {
    ...pick(report, ['score', 'level', 'label', 'summary', 'mainReason', 'categories', 'confidence', 'correlations', 'trust', 'errors', 'techniques']),
    verdict: pick(report.verdict, ['tone', 'headline']),
    findings: report.findings.map((f) => pick(f, ['id', 'detector', 'severity', 'points', 'title', 'detail', 'evidence', 'mitre', 'category', 'reliability', 'provenance', 'polarity', 'brand', 'techniques'])),
    email: {
      ...pick(email, ['from', 'replyTo', 'returnPath', 'subject', 'links', 'authResults', 'date', 'route']),
      attachments: (email.attachments ?? []).map((a) => pick(a, ['filename', 'contentType'])),
    },
    iocs: pick(report.iocs, ['urls', 'domains', 'ips', 'emails', 'attachments']),
  };
}

export function buildGolden() {
  const out = {};
  for (const sample of SAMPLES) {
    const raw = readFileSync(new URL(`../../samples/${sample.file}`, import.meta.url), 'utf8');
    out[sample.id] = legacyView(analyzeInput({ kind: 'eml', value: raw }));
  }
  return JSON.parse(JSON.stringify(out));
}

if (process.argv[1] === fileURLToPath(import.meta.url) && process.argv.includes('--write')) {
  writeFileSync(GOLDEN_PATH, `${JSON.stringify(buildGolden(), null, 2)}\n`);
  writeFileSync(BATCH_GOLDEN_PATH, `${JSON.stringify(await buildBatchGolden(), null, 2)}\n`);
  console.log(`Golden escrito en ${fileURLToPath(GOLDEN_PATH)}`);
}
