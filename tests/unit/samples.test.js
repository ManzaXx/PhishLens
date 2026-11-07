import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SAMPLES, BATCHES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';

const expected = {
  '01-legitimo-newsletter': 'safe',
  '02-legitimo-pedido': 'safe',
  '03-phishing-banco': 'critical',
  '04-phishing-correos': 'critical',
  '05-phishing-microsoft365': 'critical',
  '06-phishing-factura-adjunto': 'phishing',
  '07-phishing-avanzado': 'critical',
  '08-ruta-falsificada': 'critical',
  '09-cabeceras-trampa': 'phishing',
  '10-dominio-unicode': 'phishing',
  '11-adjunto-tipo-falso': 'critical',
  '12-pdf-activo-zip': 'critical',
};

test('hay 12 ejemplos', () => assert.equal(SAMPLES.length, 12));

for (const sample of SAMPLES) {
  test(`${sample.id} → ${expected[sample.id]}`, () => {
    const raw = readFileSync(new URL(`../../samples/${sample.file}`, import.meta.url), 'utf8');
    const report = analyzeInput({ kind: 'eml', value: raw });
    assert.equal(report.level, expected[sample.id], `score ${report.score}: ${report.findings.map((f) => f.id).join(', ')}`);
    assert.deepEqual(report.errors, []);
  });
}

// Cada regla nueva del PR3 aparece en alguna muestra temática.
const RULES = {
  '08-ruta-falsificada': ['route.private-ip-boundary', 'route.helo-mismatch', 'route.time-travel', 'route.slow-delivery'],
  '09-cabeceras-trampa': ['headers.duplicate-from', 'headers.duplicate', 'sender.display-name-address', 'sender.sender-mismatch'],
  '11-adjunto-tipo-falso': ['attachments.type-mismatch'],
  '12-pdf-activo-zip': ['attachments.pdf-active', 'attachments.archive-executable', 'attachments.encrypted-archive'],
  '10-dominio-unicode': ['lookalike.mixed-script-domain', 'lookalike.whole-script', 'lookalike.deceptive-subdomain', 'lookalike.brand-in-domain'],
};

for (const [id, rules] of Object.entries(RULES)) {
  test(`${id} contiene sus reglas`, () => {
    const raw = readFileSync(new URL(`../../samples/${id}.eml`, import.meta.url), 'utf8');
    const found = analyzeInput({ kind: 'eml', value: raw }).findings.map((f) => f.id);
    for (const rule of rules) assert.ok(found.includes(rule), `${rule} no aparece: ${found.join(', ')}`);
  });
}

test('las muestras legítimas no tienen ningún punto', () => {
  for (const id of ['01-legitimo-newsletter', '02-legitimo-pedido']) {
    const raw = readFileSync(new URL(`../../samples/${id}.eml`, import.meta.url), 'utf8');
    assert.equal(analyzeInput({ kind: 'eml', value: raw }).score, 0, id);
  }
});

test('samples/data.js está sincronizado con los .eml (npm run samples)', async () => {
  const { SAMPLE_TEXTS } = await import('../../samples/data.js');
  assert.deepEqual(Object.keys(SAMPLE_TEXTS).sort(), [...SAMPLES.map((s) => s.id), ...BATCHES.flatMap((b) => b.files)].sort());
  for (const sample of SAMPLES) {
    const raw = readFileSync(new URL(`../../samples/${sample.file}`, import.meta.url), 'utf8');
    assert.equal(SAMPLE_TEXTS[sample.id], raw, sample.id);
  }
});
