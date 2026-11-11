// Exportaciones con idioma (spec 3.1, PR15): solo cambian los textos y `lang`; los ids no.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SAMPLES, BATCHES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';
import { setLang, getLang, tr } from '../../src/i18n/index.js';
import { localizeReport } from '../../src/ui/localize.js';
import { reportToJson, stixJson } from '../../src/ui/render.js';
import { forensicReport, forensicJson, verifyForensicJson } from '../../src/intel/forensic.js';
import { findCampaigns } from '../../src/intel/campaigns.js';
import { campaignName } from '../../src/ui/campaign-reasons.js';
import { validateRules, formatRuleError } from '../../src/rules/validate.js';
import { sampleTitle, batchTitle } from '../../src/ui/samples.js';

afterEach(() => setLang('es'));

const s03 = SAMPLES.find((s) => s.file.startsWith('03'));
const raw = readFileSync(new URL(`../../samples/${s03.file}`, import.meta.url), 'utf8');
const report = analyzeInput({ kind: 'eml', value: raw });
const now = new Date('2026-11-11T10:00:00Z');

function exportIn(lang) {
  setLang(lang);
  const shown = localizeReport(report);
  const json = JSON.parse(reportToJson(shown, getLang()));
  const stix = JSON.parse(stixJson([{ key: 'k', name: 'x.eml', report: shown }], { now, lang, tr }).json);
  const forensic = forensicJson(forensicReport({ report: shown, source: { kind: 'live', name: 'x.eml', text: raw }, analyzedAt: now, version: 'test', lang, tr }));
  return { json, stix, forensic };
}

test('el mismo correo en español y en inglés: mismos ids, otro lang y otros textos', () => {
  const es = exportIn('es');
  const en = exportIn('en');
  assert.equal(es.json.lang, 'es');
  assert.equal(en.json.lang, 'en');
  assert.deepEqual(en.json.findings.map((f) => f.id), es.json.findings.map((f) => f.id));
  assert.notDeepEqual(en.json.findings.map((f) => f.title), es.json.findings.map((f) => f.title));
  assert.deepEqual(en.stix.objects.map((o) => o.id), es.stix.objects.map((o) => o.id));
  assert.equal(en.stix.id, es.stix.id);
  for (const o of en.stix.objects.filter((x) => x.created)) assert.equal(o.lang, 'en', o.id);
  for (const o of es.stix.objects.filter((x) => x.created)) assert.equal(o.lang, 'es', o.id);
  const name = (b) => b.objects.find((o) => o.type === 'indicator')?.name;
  assert.notEqual(name(en.stix), name(es.stix));
  assert.ok(verifyForensicJson(es.forensic));
  assert.ok(verifyForensicJson(en.forensic));
  const fen = JSON.parse(en.forensic);
  const fes = JSON.parse(es.forensic);
  assert.equal(fen.lang, 'en');
  assert.equal(fes.lang, 'es');
  assert.deepEqual(fen.findings.map((f) => f.id), fes.findings.map((f) => f.id));
  assert.notEqual(fen.limits, fes.limits);
  assert.notEqual(fen.verdict.headline, fes.verdict.headline);
});

test('nombre de campaña: «Campaña 1» en español y «Campaign 1» en inglés', () => {
  const c = { name: 'Campaña 1', nameRef: { code: 'campaign.name', params: { n: 1 } } };
  assert.equal(campaignName(c), 'Campaña 1');
  setLang('en');
  assert.equal(campaignName(c), 'Campaign 1');
  assert.equal(campaignName({ name: 'Campaña 2' }), 'Campaña 2');
  assert.equal(typeof findCampaigns, 'function');
});

test('errores de reglas propias en inglés', () => {
  const bad = validateRules(JSON.stringify({ phishlens: 'rules/1', rules: [{ id: 'ab', title: 'x', severity: 'grave', category: 'links', when: { field: 'subject', op: 'matches', value: 'x' } }] }));
  assert.equal(bad.ok, false);
  const es = bad.errors.map((e) => formatRuleError(e, tr));
  setLang('en');
  const en = bad.errors.map((e) => formatRuleError(e, tr));
  assert.match(es[0], /^Regla 1, `id`: tiene que tener/);
  assert.match(en[0], /^Rule 1, `id`: /);
  assert.ok(en.some((x) => /“matches” is not a supported operator/.test(x)), en.join('\n'));
  assert.ok(en.every((x, i) => x !== es[i]));
  const file = validateRules('{');
  assert.equal(formatRuleError(file.errors[0], tr), 'File: is not valid JSON');
});

test('títulos de las muestras y del lote en inglés', () => {
  assert.equal(sampleTitle(s03), 'Phishing bancario');
  setLang('en');
  assert.equal(sampleTitle(s03), 'Bank phishing');
  assert.equal(batchTitle(BATCHES[0]), 'Campaign batch (4 emails)');
  for (const s of SAMPLES) assert.ok(s.titleEn && s.titleEn !== s.title, s.id);
});
