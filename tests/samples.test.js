import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SAMPLES } from '../samples/index.js';
import { analyzeInput } from '../src/engine.js';

const expected = {
  '01-legitimo-newsletter': 'safe',
  '02-legitimo-pedido': 'safe',
  '03-phishing-banco': 'phishing',
  '04-phishing-correos': 'phishing',
  '05-phishing-microsoft365': 'phishing',
  '06-phishing-factura-adjunto': 'phishing',
  '07-phishing-avanzado': 'phishing',
};

test('hay 7 ejemplos', () => assert.equal(SAMPLES.length, 7));

for (const sample of SAMPLES) {
  test(`${sample.id} → ${expected[sample.id]}`, () => {
    const raw = readFileSync(new URL(`../samples/${sample.file}`, import.meta.url), 'utf8');
    const report = analyzeInput({ kind: 'eml', value: raw });
    assert.equal(report.level, expected[sample.id], `score ${report.score}: ${report.findings.map((f) => f.id).join(', ')}`);
    assert.deepEqual(report.errors, []);
  });
}
