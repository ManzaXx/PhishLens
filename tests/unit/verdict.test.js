// Veredicto en lenguaje llano (spec 2.3, §3).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SAMPLES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';
import { verdictFor } from '../../src/core/verdict.js';
import { rng } from '../helpers/rng.js';

const sample = (prefix) => {
  const s = SAMPLES.find((x) => x.file.startsWith(prefix));
  return analyzeInput({ kind: 'eml', value: readFileSync(new URL(`../../samples/${s.file}`, import.meta.url), 'utf8') });
};

test('muestra 03: phishing que suplanta a Santander', () => {
  const v = sample('03').verdict;
  assert.equal(v.tone, 'phishing');
  assert.equal(v.headline, 'No te fíes: es phishing');
  assert.match(v.because, /Santander/);
  assert.match(v.because, /santander-seguridad\.test/);
});

test('muestra 01: legítimo sin señales', () => {
  const v = sample('01').verdict;
  assert.equal(v.tone, 'safe');
  assert.equal(v.headline, 'Parece legítimo');
  assert.equal(v.because, 'No hemos encontrado nada que indique un engaño.');
});

test('URL suelta: el porqué no habla de quién lo envía', () => {
  const v = analyzeInput({ kind: 'url', value: 'http://192.0.2.1/login' }).verdict;
  assert.doesNotMatch(v.because, /lo envía/);
  assert.ok(v.because.length > 0);
});

test('tono y titular por nivel', () => {
  const base = { findings: [], score: 0 };
  assert.equal(verdictFor({ ...base, level: 'suspicious' }).headline, 'Ten cuidado');
  assert.equal(verdictFor({ ...base, level: 'suspicious' }).tone, 'suspicious');
  assert.equal(verdictFor({ ...base, level: 'critical' }).tone, 'phishing');
  assert.equal(verdictFor({ ...base, level: 'raro' }).tone, 'suspicious');
});

test('tres pasos en todas las muestras', () => {
  for (const s of SAMPLES) {
    const r = analyzeInput({ kind: 'eml', value: readFileSync(new URL(`../../samples/${s.file}`, import.meta.url), 'utf8') });
    assert.equal(r.verdict.steps.length, 3, s.file);
    assert.ok(r.verdict.top.length <= 5);
    assert.ok(r.verdict.top.every((f) => f.polarity !== 'trust' && f.points > 0), s.file);
    const texts = r.verdict.top.map((f) => f.plain);
    assert.equal(new Set(texts).size, texts.length, `${s.file}: texto repetido en top`);
  }
});

test('top no depende del orden de los hallazgos', () => {
  const report = sample('07');
  const ids = verdictFor(report).top.map((f) => f.id);
  const r = rng(7);
  for (let i = 0; i < 20; i++) {
    const shuffled = [...report.findings].map((f) => [r(), f]).sort((a, b) => a[0] - b[0]).map(([, f]) => f);
    assert.deepEqual(verdictFor({ ...report, findings: shuffled }).top.map((f) => f.id), ids);
  }
});
