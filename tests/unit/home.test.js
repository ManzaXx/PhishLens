// La portada dice la verdad (spec 2.3, §5): cifras sacadas del código y el motor real explicado.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DEFAULT_DETECTORS } from '../../src/core/engine.js';
import { FACTS, levelLegend } from '../../src/core/facts.js';
import { PLAIN } from '../../src/data/plain.js';
import { ATTACK_VERSION } from '../../src/data/mitre.js';

const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');

test('no quedan cifras del motor antiguo', () => {
  for (const old of ['leve 5', 'media 15', 'grave 30', 'Ocho detectores', '8</strong> detectores', '40+']) {
    assert.ok(!html.includes(old), old);
  }
});

test('FACTS sale del código', () => {
  assert.deepEqual(FACTS, { detectors: DEFAULT_DETECTORS.length, rules: Object.keys(PLAIN).length, attack: ATTACK_VERSION });
});

test('las cifras de la portada llevan data-fact y su valor sin JavaScript ya es el correcto', () => {
  for (const [key, value] of Object.entries(FACTS)) {
    const m = html.match(new RegExp(`data-fact="${key}"[^>]*>([^<]*)<`));
    assert.ok(m, `falta data-fact="${key}"`);
    assert.equal(m[1].trim(), String(value), key);
  }
});

test('una tarjeta por detector', () => {
  const cards = [...html.matchAll(/<article[^>]*data-detector="([a-z]+)"/g)].map((m) => m[1]);
  assert.deepEqual(cards.sort(), DEFAULT_DETECTORS.map((d) => d.name).sort());
});

test('leyenda: cuatro tramos contiguos de 0 a 100, igual en la página', () => {
  const legend = levelLegend();
  assert.equal(legend.length, 4);
  assert.equal(legend[0].min, 0);
  assert.equal(legend.at(-1).max, 100);
  for (let i = 1; i < legend.length; i++) assert.equal(legend[i].min, legend[i - 1].max + 1);
  assert.deepEqual(legend.map((l) => [l.min, l.max]), [[0, 24], [25, 59], [60, 79], [80, 100]]);
  assert.match(html, /data-levels/);
  for (const l of legend) assert.ok(html.includes(`${l.min}–${l.max} ${l.label}`), `${l.min}–${l.max} ${l.label}`);
});

test('«Cómo funciona» explica topes, combinaciones y confianza y enlaza a scoring.md', () => {
  const how = html.slice(html.indexOf('id="como-funciona"'), html.indexOf('id="privacidad"'));
  assert.match(how, /tope/);
  assert.match(how, /combinaciones/);
  assert.match(how, /confianza/);
  assert.match(how, /href="https:\/\/github\.com\/ManzaXx\/PhishLens\/blob\/main\/docs\/scoring\.md"/);
});

test('el informe no es una región viva entera: un aviso corto anuncia el resultado', () => {
  const report = html.match(/<section[^>]*id="report"[^>]*>/)[0];
  assert.doesNotMatch(report, /aria-live/);
  assert.match(html, /<p[^>]*id="report-status"[^>]*role="status"/);
});

test('ningún texto publicado dice «8 detectores»', () => {
  const readme = readFileSync(new URL('../../README.md', import.meta.url), 'utf8');
  for (const [name, text] of [['index.html', html], ['README.md', readme]]) {
    assert.doesNotMatch(text, /\b8 detectores\b/, name);
  }
});
