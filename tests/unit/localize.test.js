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
