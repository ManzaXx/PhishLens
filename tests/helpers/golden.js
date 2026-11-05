// Foto "golden" de los informes de las muestras: solo los campos que ya existían en la v2.1.
// Sirve para demostrar que una reestructura no cambia ningún veredicto.
// Uso: node tests/helpers/golden.js --write
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SAMPLES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';

export const GOLDEN_PATH = new URL('../unit/__golden__/samples.json', import.meta.url);

const pick = (obj, keys) => Object.fromEntries(keys.map((k) => [k, obj?.[k] ?? null]));

export function legacyView(report) {
  const { email } = report;
  return {
    ...pick(report, ['score', 'level', 'label', 'summary', 'errors', 'techniques']),
    findings: report.findings.map((f) => pick(f, ['id', 'detector', 'severity', 'points', 'title', 'detail', 'evidence', 'mitre'])),
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
  console.log(`Golden escrito en ${fileURLToPath(GOLDEN_PATH)}`);
}
