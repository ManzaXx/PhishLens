// La herramienta de evaluación (tools/eval.mjs, docs/evaluation.md): matriz de confusión, tasas por regla
// y el informe sobre las muestras empaquetadas, que no debe tener ningún legítimo marcado como phishing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { readManifest, sampleEntries, analyzeCorpus, confusion, ruleRates, histogram, evaluate, toMarkdown, THRESHOLDS } from '../../tools/eval.mjs';

const r = (label, score, ids = []) => ({ file: `${label}-${score}.eml`, label, note: '', score, level: 'x', ids, errors: 0 });

test('readManifest acepta fichero,etiqueta[,nota] y rechaza etiquetas inventadas', () => {
  const rows = readManifest('# comentario\n\na.eml,legit,newsletter real\nb.eml,phishing,enlace .top, visto el 3/11\n');
  assert.deepEqual(rows, [
    { file: 'a.eml', label: 'legit', note: 'newsletter real' },
    { file: 'b.eml', label: 'phishing', note: 'enlace .top,visto el 3/11' },
  ]);
  assert.throws(() => readManifest('c.eml,spam'), /esperaba fichero,legit\|phishing/);
  assert.throws(() => readManifest(',legit'), /no válida/);
});

test('confusion: aciertos, fallos y tasas a un umbral', () => {
  const results = [r('phishing', 90), r('phishing', 70), r('phishing', 40), r('legit', 10), r('legit', 30), r('legit', 65)];
  const c = confusion(results, 60);
  assert.deepEqual([c.tp, c.fn, c.fp, c.tn], [2, 1, 1, 2]);
  assert.equal(c.precision, 2 / 3);
  assert.equal(c.recall, 2 / 3);
  assert.equal(c.fpr, 1 / 3);
  const loose = confusion(results, 25);
  assert.deepEqual([loose.tp, loose.fn, loose.fp, loose.tn], [3, 0, 2, 1]);
  assert.deepEqual(confusion([], 60), { tp: 0, fn: 0, fp: 0, tn: 0, precision: 0, recall: 0, fpr: 0 });
});

test('ruleRates: las reglas que más saltan en legítimos van primero', () => {
  const results = [r('legit', 10, ['a.x', 'b.y']), r('legit', 20, ['a.x']), r('phishing', 80, ['b.y', 'c.z']), r('phishing', 90, ['c.z'])];
  const rates = ruleRates(results);
  assert.deepEqual(rates.map((x) => x.id), ['a.x', 'b.y', 'c.z']);
  assert.deepEqual(rates[0], { id: 'a.x', inLegit: 2, legit: 2, inPhish: 0, phishing: 2, legitRate: 1, phishRate: 0 });
  assert.equal(rates[2].phishRate, 1);
});

test('histogram: diez tramos y cada nota cae en el suyo (100 va al último)', () => {
  const h = histogram([r('legit', 0), r('legit', 9), r('legit', 10), r('phishing', 100), r('phishing', 95)]);
  assert.equal(h.length, 10);
  assert.deepEqual([h[0].legit, h[1].legit, h[9].phishing], [2, 1, 2]);
  assert.deepEqual([h[9].from, h[9].to], [90, 100]);
});

test('evaluate + toMarkdown: listas nominales con las reglas, sin contenido del correo', () => {
  const ev = evaluate([r('legit', 70, ['links.ip']), r('legit', 30, ['language.urgency']), r('phishing', 50, ['auth.spf']), r('phishing', 85, ['auth.spf'])]);
  assert.deepEqual(ev.falsePositives.map((x) => x.file), ['legit-70.eml']);
  assert.deepEqual(ev.borderline.map((x) => x.file), ['legit-30.eml']);
  assert.deepEqual(ev.falseNegatives.map((x) => x.file), ['phishing-50.eml']);
  const md = toMarkdown(ev, { source: 'prueba', date: '2026-11-13' });
  assert.match(md, /4 correos \(2 legítimos, 2 phishing\) · 2026-11-13/);
  assert.match(md, /`legit-70\.eml` → 70 \(x\): links\.ip/);
  assert.match(md, /\| `auth\.spf` \| 0\/2 \| 2\/2 \|/);
  assert.deepEqual(THRESHOLDS.map((t) => t.min), [25, 60]);
});

test('las muestras empaquetadas: ningún legítimo a ≥ 60 y ningún phishing por debajo de 25', () => {
  const dir = fileURLToPath(new URL('../../samples/', import.meta.url));
  const entries = sampleEntries();
  assert.equal(entries.filter((e) => e.label === 'legit').length, 6);
  const ev = evaluate(analyzeCorpus(dir, entries));
  assert.equal(ev.total, 17);
  assert.deepEqual(ev.falsePositives, []);
  assert.deepEqual(ev.errors, []);
  assert.equal(ev.thresholds[0].fn, 0, 'todo el phishing es al menos sospechoso');
  // Las muestras no aspiran a más que esto; las tasas reales salen de un corpus propio (docs/evaluation.md).
  assert.ok(ev.thresholds[1].precision === 1);
});
