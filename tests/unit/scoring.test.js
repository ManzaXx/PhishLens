import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { finding } from '../../src/core/finding.js';
import { scoreFindings, levelFor, CATEGORY_MAX, SCALE } from '../../src/core/scoring.js';

// Generador con semilla fija (mulberry32): los casos aleatorios son siempre los mismos.
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Ids reales, sacados de los informes de las muestras.
const golden = JSON.parse(readFileSync(new URL('./__golden__/samples.json', import.meta.url), 'utf8'));
const SAMPLE_IDS = [...new Set(Object.values(golden).flatMap((r) => r.findings.map((f) => f.id)))];
const SEVERITIES = ['info', 'low', 'medium', 'high'];
const RELIABILITIES = ['high', 'medium', 'low'];

const make = (id, severity = 'high', extra = {}) => finding({ id, detector: id.split('.')[0], severity, title: id, detail: id, ...extra });

function randomFinding(r) {
  const id = SAMPLE_IDS[Math.floor(r() * SAMPLE_IDS.length)];
  return make(id, SEVERITIES[Math.floor(r() * 4)], { reliability: RELIABILITIES[Math.floor(r() * 3)] });
}
const randomSet = (r) => Array.from({ length: Math.floor(r() * 15) }, () => randomFinding(r));
function shuffle(list, r) {
  const out = [...list];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

test('propiedades: nota acotada, monótona e independiente del orden (500 casos)', () => {
  const r = rng(2026);
  for (let i = 0; i < 500; i++) {
    const set = randomSet(r);
    const result = scoreFindings(set);
    assert.ok(result.score >= 0 && result.score <= 100, `score ${result.score}`);
    for (const c of result.categories) assert.ok(c.score >= 0 && c.score <= c.max, `${c.id} ${c.score}`);
    const more = scoreFindings([...set, randomFinding(r)]);
    assert.ok(more.score >= result.score, `añadir bajó la nota: ${result.score} → ${more.score}`);
    assert.deepEqual(scoreFindings(shuffle(set, r)), result);
  }
});

test('300 hallazgos de enlaces no pasan del máximo de la categoría', () => {
  const result = scoreFindings(Array.from({ length: 300 }, () => make('links.mismatch', 'high', { reliability: 'high' })));
  assert.ok(result.categories.find((c) => c.id === 'links').score <= 20);
  assert.ok(result.score <= 100);
});

test('las seis categorías salen siempre, en orden y con su máximo', () => {
  const { categories } = scoreFindings([]);
  assert.deepEqual(categories.map((c) => [c.id, c.max, c.score]), Object.entries(CATEGORY_MAX).map(([id, max]) => [id, max, 0]));
  assert.equal(SCALE, 40);
});

test('A: ocho enlaces sospechosos dan «sospechoso», no phishing', () => {
  const result = scoreFindings(Array.from({ length: 8 }, () => make('links.mismatch', 'medium', { reliability: 'medium' })));
  assert.equal(result.level, 'suspicious');
});

test('B: suplantación + .exe + DMARC fallido dan «crítico»', () => {
  const result = scoreFindings([
    make('sender.brand-impersonation', 'high', { reliability: 'high', brand: 'PayPal' }),
    make('attachments.dangerous', 'high', { reliability: 'high' }),
    make('auth.dmarc-unaligned', 'high'),
  ]);
  assert.equal(result.level, 'critical');
  assert.ok(result.correlations.some((c) => c.id === 'brand-auth'));
});

test('una firma verificada rebaja lenguaje e infraestructura, nunca suplantación ni enlaces', () => {
  const risk = [
    make('language.urgency', 'medium'), make('headers.mailer', 'medium'),
    make('sender.brand-impersonation', 'high'), make('links.mismatch', 'high'), make('attachments.dangerous', 'high'),
  ];
  const trust = make('auth.dkim-body-verified', 'info', { polarity: 'trust', provenance: 'verified', reliability: 'high' });
  const without = Object.fromEntries(scoreFindings(risk).categories.map((c) => [c.id, c.score]));
  const result = scoreFindings([...risk, trust]);
  const withTrust = Object.fromEntries(result.categories.map((c) => [c.id, c.score]));
  assert.ok(Math.abs(withTrust.language - without.language / 2) <= 0.1);
  assert.ok(Math.abs(withTrust.infrastructure - without.infrastructure / 2) <= 0.1);
  for (const id of ['sender', 'links', 'attachments']) assert.equal(withTrust[id], without[id]);
  assert.deepEqual(result.trust, ['auth.dkim-body-verified']);
});

test('solo señales a favor: nota 0 y sin correlaciones', () => {
  const result = scoreFindings([make('auth.dkim-body-verified', 'info', { polarity: 'trust', provenance: 'verified' })]);
  assert.equal(result.score, 0);
  assert.equal(result.level, 'safe');
  assert.deepEqual(result.correlations, []);
  assert.equal(result.mainReason, 'No se han encontrado señales de riesgo.');
});

const PAIRS = {
  'brand-auth': [make('sender.brand-impersonation'), make('auth.dmarc-unaligned', 'medium')],
  'brand-credentials': [make('sender.display-name-address'), make('html.form', 'medium')],
  'attachment-pressure': [make('attachments.double-extension'), make('language.urgency', 'low')],
  'lookalike-same-brand': [make('sender.brand-impersonation', 'high', { brand: 'PayPal' }), make('lookalike.typosquat', 'high', { category: 'links', brand: 'PayPal' })],
};

for (const [id, pair] of Object.entries(PAIRS)) {
  test(`correlación ${id}: se cumple con su par y no con info ni trust`, () => {
    assert.ok(scoreFindings(pair).correlations.some((c) => c.id === id));
    const [first, second] = pair;
    const weak = { ...second, severity: 'info' };
    assert.ok(!scoreFindings([first, weak]).correlations.some((c) => c.id === id), 'info');
    const trust = { ...second, polarity: 'trust' };
    assert.ok(!scoreFindings([first, trust]).correlations.some((c) => c.id === id), 'trust');
  });
}

test('lookalike en enlaces de otra marca no correlaciona con el remitente', () => {
  const result = scoreFindings([make('sender.brand-impersonation', 'high', { brand: 'PayPal' }), make('lookalike.typosquat', 'high', { category: 'links', brand: 'Apple' })]);
  assert.ok(!result.correlations.some((c) => c.id === 'lookalike-same-brand'));
});

test('como mucho dos correlaciones cuentan para la nota', () => {
  const findings = [
    make('sender.brand-impersonation', 'low', { reliability: 'low' }), make('auth.dmarc-unaligned', 'medium', { reliability: 'low' }),
    make('html.form', 'low', { reliability: 'low' }), make('attachments.macro', 'low', { reliability: 'low' }),
    make('language.threat', 'low', { reliability: 'low' }),
  ];
  const result = scoreFindings(findings);
  assert.equal(result.correlations.length, 3);
  // baseScore es la nota antes de las correlaciones; solo se aplican dos.
  const expected = [0, 1].reduce((t) => t + (100 - t) * 0.25, result.baseScore);
  assert.ok(Math.abs(result.score - expected) <= 1, `${result.score} vs ${expected}`);
});

test('motivo principal: correlación o las dos categorías con más peso', () => {
  assert.equal(scoreFindings(PAIRS['brand-auth']).mainReason, 'Motivo principal: Suplantación de marca con autenticación fallida.');
  assert.equal(scoreFindings([make('links.mismatch'), make('language.urgency', 'low')]).mainReason, 'Pesa sobre todo: Enlaces y contenido y Lenguaje.');
  assert.equal(scoreFindings([make('links.mismatch')]).mainReason, 'Pesa sobre todo: Enlaces y contenido.');
});

test('levelFor: fronteras de los cuatro niveles', () => {
  assert.equal(levelFor(80).level, 'critical');
  assert.equal(levelFor(80).label, 'Phishing casi seguro');
  assert.equal(levelFor(79).level, 'phishing');
  assert.equal(levelFor(25).level, 'suspicious');
  assert.equal(levelFor(24).level, 'safe');
});

test('marca en la ruta de un enlace a una IP que pide acceso: dos correlaciones', () => {
  const result = scoreFindings([make('links.ip', 'high'), make('links.brand-in-path', 'medium'), make('links.insecure-login', 'medium')]);
  assert.deepEqual(result.correlations.map((c) => c.id), ['brand-credentials', 'brand-raw-ip']);
  assert.equal(result.level, 'phishing');
});

test('sin cabecera de autenticación no es «autenticación fallida»', () => {
  const result = scoreFindings([make('sender.brand-impersonation'), make('auth.missing', 'low'), make('auth.dkim-weak', 'low')]);
  assert.ok(!result.correlations.some((c) => c.id === 'brand-auth'));
});

test('un dominio parecido en un enlace cuenta como marca suplantada para pedir credenciales', () => {
  const result = scoreFindings([make('lookalike.brand-in-domain', 'high', { category: 'links', brand: 'BBVA' }), make('language.credentials', 'high', { reliability: 'low' })]);
  assert.ok(result.correlations.some((c) => c.id === 'brand-credentials'));
});

test('marca en la ruta de un enlace normal + texto de inicio de sesión no es suplantación', () => {
  const result = scoreFindings([make('links.brand-in-path', 'medium'), make('language.credentials', 'high', { reliability: 'low' })]);
  assert.ok(!result.correlations.some((c) => c.id === 'brand-credentials'));
});

test('pide credenciales y da un enlace sospechoso para ello', () => {
  const result = scoreFindings([make('language.credentials', 'high', { reliability: 'low' }), make('links.shortener', 'medium')]);
  assert.ok(result.correlations.some((c) => c.id === 'credentials-link'));
  assert.ok(result.level !== 'safe');
});
