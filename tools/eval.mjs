// Evaluación del motor sobre un corpus etiquetado (auditoría 3.1, P8). Uso:
//
//   npm run eval                      → evalúa las muestras de samples/ (etiqueta según el nombre)
//   npm run eval -- corpus/           → evalúa un corpus propio con manifest.csv (fuera de git)
//   npm run eval -- --write-docs      → además reescribe el bloque de resultados de docs/evaluation.md
//                                       (solo con las muestras: un corpus propio nunca entra en la documentación)
//
// manifest.csv: una línea por correo, `fichero,etiqueta[,nota]`, etiqueta `legit` o `phishing`.
// Las líneas que empiezan por # se ignoran. Solo se imprimen nombres de fichero e ids de reglas: nunca el contenido.
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeInput } from '../src/core/engine.js';
import { LEVELS } from '../src/core/scoring.js';
import { SAMPLES } from '../samples/index.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const SAMPLES_DIR = join(ROOT, 'samples');
const DOCS = join(ROOT, 'docs/evaluation.md');
const START = '<!-- eval:start -->';
const END = '<!-- eval:end -->';

/** Umbrales que se evalúan: a partir de «Sospechoso» y a partir de «Probable phishing». */
export const THRESHOLDS = [
  { id: 'suspicious', label: 'Sospechoso o peor (≥ 25)', min: LEVELS.find((l) => l.level === 'suspicious').min },
  { id: 'phishing', label: 'Probable phishing o peor (≥ 60)', min: LEVELS.find((l) => l.level === 'phishing').min },
];

/** Lee manifest.csv: [{ file, label, note }]. Lanza si una etiqueta no es legit|phishing. */
export function readManifest(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const [file, label, ...rest] = line.split(',').map((s) => s.trim());
    if (!file || !['legit', 'phishing'].includes(label)) throw new Error(`manifest: línea no válida «${raw}» (esperaba fichero,legit|phishing)`);
    out.push({ file, label, note: rest.join(',') });
  }
  return out;
}

/** Entradas de las muestras empaquetadas: la etiqueta sale del nombre (NN-legitimo-… es legit). */
export function sampleEntries() {
  return SAMPLES.map((s) => ({ file: s.file, label: /-legitimo-/.test(s.id) ? 'legit' : 'phishing', note: s.title }));
}

/** Analiza cada correo del corpus: [{ file, label, note, score, level, ids }]. */
export function analyzeCorpus(dir, entries) {
  return entries.map((e) => {
    const report = analyzeInput({ kind: 'eml', value: readFileSync(join(dir, e.file), 'utf8') });
    const ids = [...new Set(report.findings.filter((f) => f.polarity !== 'trust' && f.severity !== 'info').map((f) => f.id))].sort();
    return { ...e, score: report.score, level: report.level, ids, errors: report.errors.length };
  });
}

const rate = (n, d) => (d ? n / d : 0);
const pct = (x) => `${(100 * x).toFixed(0)} %`;

/** Matriz de confusión y tasas para un umbral. */
export function confusion(results, min) {
  const flagged = (r) => r.score >= min;
  const tp = results.filter((r) => r.label === 'phishing' && flagged(r)).length;
  const fn = results.filter((r) => r.label === 'phishing' && !flagged(r)).length;
  const fp = results.filter((r) => r.label === 'legit' && flagged(r)).length;
  const tn = results.filter((r) => r.label === 'legit' && !flagged(r)).length;
  return { tp, fn, fp, tn, precision: rate(tp, tp + fp), recall: rate(tp, tp + fn), fpr: rate(fp, fp + tn) };
}

/** Por regla: en cuántos legítimos y en cuántos phishing salta. Ordenado por tasa en legítimos (los sospechosos de falso positivo primero). */
export function ruleRates(results) {
  const legit = results.filter((r) => r.label === 'legit');
  const phish = results.filter((r) => r.label === 'phishing');
  const ids = [...new Set(results.flatMap((r) => r.ids))];
  return ids.map((id) => {
    const inLegit = legit.filter((r) => r.ids.includes(id)).length;
    const inPhish = phish.filter((r) => r.ids.includes(id)).length;
    return { id, inLegit, legit: legit.length, inPhish, phishing: phish.length, legitRate: rate(inLegit, legit.length), phishRate: rate(inPhish, phish.length) };
  }).sort((a, b) => b.legitRate - a.legitRate || b.phishRate - a.phishRate || a.id.localeCompare(b.id));
}

/** Histograma de notas por tramo de 10, por clase. */
export function histogram(results) {
  const bins = Array.from({ length: 10 }, (_, i) => ({ from: i * 10, to: i === 9 ? 100 : i * 10 + 9, legit: 0, phishing: 0 }));
  for (const r of results) bins[Math.min(9, Math.floor(r.score / 10))][r.label]++;
  return bins;
}

/** Todo junto, listo para imprimir o comparar. */
export function evaluate(results) {
  return {
    total: results.length,
    legit: results.filter((r) => r.label === 'legit').length,
    phishing: results.filter((r) => r.label === 'phishing').length,
    thresholds: THRESHOLDS.map((t) => ({ ...t, ...confusion(results, t.min) })),
    rules: ruleRates(results),
    histogram: histogram(results),
    falsePositives: results.filter((r) => r.label === 'legit' && r.score >= THRESHOLDS[1].min),
    borderline: results.filter((r) => r.label === 'legit' && r.score >= THRESHOLDS[0].min && r.score < THRESHOLDS[1].min),
    falseNegatives: results.filter((r) => r.label === 'phishing' && r.score < THRESHOLDS[1].min),
    errors: results.filter((r) => r.errors > 0),
  };
}

export function toMarkdown(ev, { source, date = new Date().toISOString().slice(0, 10) } = {}) {
  const lines = [];
  lines.push(`Corpus: ${source} · ${ev.total} correos (${ev.legit} legítimos, ${ev.phishing} phishing) · ${date}`, '');
  lines.push('| Umbral | Aciertos (phishing) | Falsos negativos | Falsos positivos | Legítimos bien | Precisión | Cobertura | Tasa de falsos positivos |');
  lines.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
  for (const t of ev.thresholds) lines.push(`| ${t.label} | ${t.tp} | ${t.fn} | ${t.fp} | ${t.tn} | ${pct(t.precision)} | ${pct(t.recall)} | ${pct(t.fpr)} |`);
  lines.push('', '**Distribución de notas**', '', '| Tramo | Legítimos | Phishing |', '| --- | --- | --- |');
  for (const b of ev.histogram) if (b.legit || b.phishing) lines.push(`| ${b.from}–${b.to} | ${b.legit} | ${b.phishing} |`);
  const list = (title, rows, empty) => {
    lines.push('', `**${title}**`, '');
    if (!rows.length) lines.push(`- ${empty}`);
    for (const r of rows) lines.push(`- \`${r.file}\` → ${r.score} (${r.level}): ${r.ids.join(', ') || 'sin señales'}`);
  };
  list('Legítimos marcados como phishing (≥ 60)', ev.falsePositives, 'ninguno');
  list('Legítimos en «Sospechoso» (25–59)', ev.borderline, 'ninguno');
  list('Phishing por debajo de «Probable phishing» (< 60)', ev.falseNegatives, 'ninguno');
  lines.push('', '**Reglas por clase** (en cuántos legítimos y en cuántos phishing salta cada una; arriba, las que más saltan en legítimos)', '');
  lines.push('| Regla | Legítimos | Phishing |', '| --- | --- | --- |');
  for (const r of ev.rules) lines.push(`| \`${r.id}\` | ${r.inLegit}/${r.legit} | ${r.inPhish}/${r.phishing} |`);
  if (ev.errors.length) lines.push('', `**Detectores caídos** en: ${ev.errors.map((r) => `\`${r.file}\``).join(', ')}`);
  return `${lines.join('\n')}\n`;
}

function loadCorpus(arg) {
  if (!arg) {
    const own = join(ROOT, 'corpus');
    if (existsSync(join(own, 'manifest.csv'))) return { dir: own, entries: readManifest(readFileSync(join(own, 'manifest.csv'), 'utf8')), source: 'corpus/ (propio)' };
    return { dir: SAMPLES_DIR, entries: sampleEntries(), source: 'samples/ (muestras empaquetadas)' };
  }
  const dir = resolve(arg);
  if (dir === SAMPLES_DIR) return { dir, entries: sampleEntries(), source: 'samples/ (muestras empaquetadas)' };
  const manifest = join(dir, 'manifest.csv');
  if (!existsSync(manifest)) throw new Error(`no hay manifest.csv en ${dir} (ficheros vistos: ${readdirSync(dir).length})`);
  return { dir, entries: readManifest(readFileSync(manifest, 'utf8')), source: `${arg} (propio)` };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const writeDocs = args.includes('--write-docs');
  const { dir, entries, source } = loadCorpus(args.find((a) => !a.startsWith('--')));
  const md = toMarkdown(evaluate(analyzeCorpus(dir, entries)), { source });
  process.stdout.write(md);
  if (writeDocs) {
    if (dir !== SAMPLES_DIR) throw new Error('--write-docs solo con las muestras empaquetadas: un corpus propio no entra en la documentación');
    const doc = readFileSync(DOCS, 'utf8');
    const a = doc.indexOf(START);
    const b = doc.indexOf(END);
    if (a === -1 || b === -1) throw new Error(`faltan los marcadores ${START} / ${END} en docs/evaluation.md`);
    writeFileSync(DOCS, `${doc.slice(0, a + START.length)}\n${md}${doc.slice(b)}`);
    console.error(`Resultados escritos en ${DOCS}`);
  }
}
