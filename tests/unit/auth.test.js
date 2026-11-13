import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseEml } from '../../src/parser/eml.js';
import { detect } from '../../src/detectors/auth.js';

const mail = (auth) => parseEml(`From: a@paypal.com\nSubject: x\n${auth ? `Authentication-Results: mx.example.com; ${auth}\n` : ''}\nhola`);
const ids = (findings) => findings.map((f) => `${f.id}:${f.severity}`);

test('SPF fail es grave y softfail medio', () => {
  assert.deepEqual(ids(detect(mail('spf=fail smtp.mailfrom=paypal.com; dkim=pass; dmarc=pass'))), ['auth.spf:high']);
  assert.deepEqual(ids(detect(mail('spf=softfail; dkim=pass; dmarc=pass'))), ['auth.spf:medium']);
});

test('DKIM y DMARC fail son graves', () => {
  assert.deepEqual(ids(detect(mail('spf=pass; dkim=fail; dmarc=fail header.from=paypal.com'))), ['auth.dkim:high', 'auth.dmarc:high']);
});

// Desde la auditoría 3.1 (P7) es informativo: no suma puntos. La confianza del análisis sigue bajando
// por «autenticación ausente» (tests/unit/confidence.test.js).
test('sin Authentication-Results es informativo, no una señal de riesgo', () => {
  assert.deepEqual(ids(detect(mail(null))), ['auth.missing:info']);
});

test('todo pass no genera hallazgos', () => {
  assert.deepEqual(detect(mail('spf=pass; dkim=pass; dmarc=pass')), []);
});

test('sin cabeceras no opina', () => {
  assert.deepEqual(detect(parseEml('solo texto')), []);
});

test('cada hallazgo lleva puntos según severidad', () => {
  const [f] = detect(mail('spf=fail; dkim=pass; dmarc=pass'));
  assert.equal(f.points, 30);
  assert.equal(f.detector, 'auth');
  assert.ok(f.title && f.detail && f.evidence);
});
