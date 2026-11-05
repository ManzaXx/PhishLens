import { test } from 'node:test';
import assert from 'node:assert/strict';
import { technique, techniqueFor, techniquesFor, TECHNIQUES, ATTACK_VERSION } from '../../src/data/mitre.js';
import { finding } from '../../src/core/finding.js';
import { analyzeInput } from '../../src/core/engine.js';

const idsOf = (findingId) => techniquesFor(findingId).map((t) => t.id);

test('versión de ATT&CK fijada', () => {
  assert.equal(ATTACK_VERSION, '20.1');
});

test('cada familia de hallazgo tiene sus técnicas (ATT&CK 20.1)', () => {
  assert.deepEqual(idsOf('links.mismatch'), ['T1566.002', 'T1204.001']);
  assert.deepEqual(idsOf('attachments.dangerous'), ['T1566.001', 'T1204.002']);
  assert.deepEqual(idsOf('attachments.macro'), ['T1566.001', 'T1204.002']);
  assert.deepEqual(idsOf('attachments.double-extension'), ['T1036.007', 'T1204.002']);
  assert.deepEqual(idsOf('attachments.rtl-override'), ['T1036.002', 'T1204.002']);
  // T1656 y T1672 se revocaron en ATT&CK 20: ahora son T1684.001 y T1684.002.
  assert.deepEqual(idsOf('sender.brand-impersonation'), ['T1684.001']);
  assert.deepEqual(idsOf('auth.forged-results'), ['T1684.002']);
  assert.deepEqual(idsOf('route.helo-mismatch'), ['T1684.002']);
  assert.deepEqual(idsOf('route.time-travel'), ['T1684.002']);
  assert.deepEqual(idsOf('route.private-ip-boundary'), ['T1684.002']);
  assert.deepEqual(idsOf('headers.duplicate-from'), ['T1684.002']);
  assert.deepEqual(idsOf('lookalike.typosquat'), ['T1583.001']);
  assert.deepEqual(idsOf('html.form'), ['T1598']);
  assert.deepEqual(idsOf('headers.mailer'), []);
  assert.deepEqual(idsOf('route.slow-delivery'), []);
  assert.deepEqual(idsOf('input.no-headers'), []);
  assert.equal(techniqueFor('input.no-headers'), null);
});

test('cada técnica tiene nombre, táctica, motivo y URL oficial', () => {
  for (const id of Object.keys(TECHNIQUES)) {
    const t = technique(id);
    assert.ok(t.name && t.tactic && t.why, id);
    const [base, sub] = id.split('.');
    assert.equal(t.url, `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ''}`);
  }
});

test('finding(): mitre es la primera técnica y techniques la lista completa', () => {
  const f = finding({ id: 'links.ip', detector: 'links', severity: 'high', title: 't', detail: 'd' });
  assert.equal(f.mitre.id, 'T1566.002');
  assert.deepEqual(f.techniques.map((t) => t.id), ['T1566.002', 'T1204.001']);
  assert.equal(f.techniques[1].tactic, 'Execution');
});

test('el informe junta las técnicas sin repetir', () => {
  const r = analyzeInput({ kind: 'url', value: 'http://192.168.0.1/paypal/login' });
  assert.deepEqual(r.techniques.map((t) => t.id), ['T1566.002', 'T1204.001']);
});

test('no tener cabeceras de autenticación no es falsificarlas: auth.missing no tiene técnica', () => {
  assert.deepEqual(techniquesFor('auth.missing'), []);
});
