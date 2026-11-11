// Informe localizado (spec 3.1, PR15): la interfaz traduce el informe en un solo sitio y cae al español.
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SAMPLES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';
import { setLang, tr, _setDictionaries } from '../../src/i18n/index.js';
import { localizeReport, missingEnglish } from '../../src/ui/localize.js';

afterEach(() => { setLang('es'); _setDictionaries(null); });

const read = (s) => readFileSync(new URL(`../../samples/${s.file}`, import.meta.url), 'utf8');
const analyzed = SAMPLES.filter((s) => s.file).map((s) => ({ s, r: analyzeInput({ kind: s.kind ?? 'eml', value: read(s) }) }));
const sample = (prefix) => analyzed.find(({ s }) => s.file.startsWith(prefix)).r;

test('tr: en español devuelve el texto de reserva', () => {
  assert.equal(tr('level.safe', {}, 'reserva'), 'reserva');
});

test('tr: en inglés traduce con todos los parámetros y cae entero al español si falta uno', () => {
  _setDictionaries({ es: {}, en: { 'x.t': 'Pretends to be {brand} from {domain}', 'w.word': 'subject' } });
  setLang('en');
  assert.equal(tr('x.t', { brand: 'PayPal', domain: 'a.b' }, 'es'), 'Pretends to be PayPal from a.b');
  assert.equal(tr('x.t', { brand: 'PayPal' }, 'texto en español'), 'texto en español');
  assert.equal(tr('x.t', undefined, 'texto en español'), 'texto en español');
  assert.equal(tr('no.existe', {}, 'reserva'), 'reserva');
});

test('tr: un parámetro {key} se traduce y un valor con llaves sale literal', () => {
  _setDictionaries({ es: {}, en: { 'x.t': 'Odd {field}: {brand}', 'field.subject': 'subject' } });
  setLang('en');
  assert.equal(tr('x.t', { field: { key: 'field.subject' }, brand: '{brand}' }, 'es'), 'Odd subject: {brand}');
});

test('tr: con count numérico elige el plural', () => {
  _setDictionaries({ es: {}, en: { 'x.t.one': 'Link', 'x.t.other': 'Link ({count} links)' } });
  setLang('en');
  assert.equal(tr('x.t', { count: 3 }, 'es'), 'Link (3 links)');
  assert.equal(tr('x.t', { count: 1 }, 'es'), 'Link');
});

test('localizeReport: en español es la identidad para cada muestra', () => {
  for (const { s, r } of analyzed) assert.deepEqual(localizeReport(r), r, s.file);
});

test('localizeReport: en inglés traduce nivel y categorías, y no muta el original', () => {
  const r = sample('03');
  const before = structuredClone(r);
  setLang('en');
  const en = localizeReport(r);
  assert.equal(en.label, 'Phishing almost certain');
  assert.equal(en.categories.find((c) => c.id === 'authentication').label, 'Authentication');
  for (const c of en.correlations) assert.notEqual(c.label, r.correlations.find((x) => x.id === c.id).label, c.id);
  assert.deepEqual(r, before);
});

test('localizeReport: un hallazgo sin params cuya plantilla pide {brand} se queda en español (historial 3.0)', () => {
  _setDictionaries({ es: {}, en: { 'rule.sender.brand-impersonation.title': 'Pretends to be {brand}' } });
  setLang('en');
  const f = { id: 'sender.brand-impersonation', detector: 'sender', title: 'Se hace pasar por PayPal', detail: 'd', plain: 'p' };
  const out = localizeReport({ level: 'safe', label: 'x', categories: [], correlations: [], findings: [f] });
  assert.equal(out.findings[0].title, 'Se hace pasar por PayPal');
  assert.deepEqual(missingEnglish({ findings: [f] }).filter((m) => m.startsWith('rule.sender.brand-impersonation.title')),
    ['rule.sender.brand-impersonation.title: falta {brand}']);
});

test('localizeReport: las reglas propias salen tal cual', () => {
  setLang('en');
  const f = { id: 'custom.mia', detector: 'custom', custom: true, title: 'Mi regla', detail: 'Mi detalle', plain: 'Mi regla' };
  const out = localizeReport({ level: 'safe', label: 'x', categories: [], correlations: [], findings: [f] });
  assert.deepEqual(out.findings[0], f);
});

const HEADLINES_EN = ['Looks legitimate', 'Be careful', "Don't trust it: it's phishing"];

test('en inglés, cada muestra trae veredicto, pasos, confianza, resumen y autenticación traducidos', () => {
  for (const { s, r } of analyzed) {
    setLang('en');
    const en = localizeReport(r);
    assert.deepEqual(missingEnglish(r), [], s.file);
    assert.ok(HEADLINES_EN.includes(en.verdict.headline), `${s.file}: ${en.verdict.headline}`);
    assert.equal(en.verdict.steps.length, 3, s.file);
    en.verdict.steps.forEach((step, i) => assert.notEqual(step, r.verdict.steps[i], `${s.file}: ${step}`));
    assert.notEqual(en.verdict.because, r.verdict.because, s.file);
    en.confidence.reasons.forEach((x, i) => assert.notEqual(x, r.confidence.reasons[i], `${s.file}: ${x}`));
    assert.notEqual(en.summary, r.summary, s.file);
    assert.notEqual(en.mainReason, r.mainReason, s.file);
    for (const k of ['spf', 'dkim', 'dmarc']) if (r.auth[k].detail) assert.notEqual(en.auth[k].detail, r.auth[k].detail, `${s.file} ${k}`);
    for (const [i, h] of r.auth.headers.entries()) assert.notEqual(en.auth.headers[i].why, h.why, s.file);
    en.verdict.top.forEach((f, i) => assert.equal(f.title, en.findings.find((x) => x.id === r.verdict.top[i].id).title));
    setLang('es');
    assert.deepEqual(localizeReport(r), r, s.file);
  }
});

test('el consejo en inglés mantiene INCIBE y el 017', () => {
  setLang('en');
  const en = localizeReport(sample('03'));
  assert.ok(en.verdict.steps.some((x) => /In Spain you can call INCIBE on 017/.test(x)) || !sample('03').verdict.stepCodes.includes('report.advice.report'));
  assert.match(tr('report.advice.report', {}, 'es'), /In Spain you can call INCIBE on 017/);
});

test('un informe de la 3.0 sin referencias se queda en español sin errores', () => {
  const r = structuredClone(sample('03'));
  delete r.summaryRef; delete r.mainReasonRef;
  delete r.verdict.headlineCode; delete r.verdict.becauseRef; delete r.verdict.stepCodes;
  delete r.confidence.codes;
  for (const k of ['spf', 'dkim', 'dmarc']) delete r.auth[k].detailRef;
  for (const h of r.auth.headers) delete h.whyRef;
  for (const f of r.findings) delete f.params;
  setLang('en');
  const en = localizeReport(r);
  assert.equal(en.verdict.headline, r.verdict.headline);
  assert.deepEqual(en.verdict.steps, r.verdict.steps);
  assert.equal(en.summary, r.summary);
  assert.equal(en.mainReason, r.mainReason);
  assert.deepEqual(en.confidence.reasons, r.confidence.reasons);
  assert.equal(en.auth.spf.detail, r.auth.spf.detail);
  assert.equal(en.label, 'Phishing almost certain');
});
