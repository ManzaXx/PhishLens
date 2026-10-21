import { test } from 'node:test';
import assert from 'node:assert/strict';
import { techniqueFor } from '../src/data/mitre.js';
import { finding } from '../src/detectors/finding.js';
import { analyzeInput } from '../src/engine.js';

test('cada familia de hallazgo tiene su técnica ATT&CK', () => {
  assert.equal(techniqueFor('links.mismatch').id, 'T1566.002');
  assert.equal(techniqueFor('attachments.dangerous').id, 'T1566.001');
  assert.equal(techniqueFor('attachments.double-extension').id, 'T1036.007');
  assert.equal(techniqueFor('attachments.rtl-override').id, 'T1036.002');
  assert.equal(techniqueFor('sender.brand-impersonation').id, 'T1656');
  assert.equal(techniqueFor('auth.dmarc').id, 'T1672');
  assert.equal(techniqueFor('lookalike.typosquat').id, 'T1583.001');
  assert.equal(techniqueFor('html.form').id, 'T1598');
  assert.equal(techniqueFor('input.no-headers'), null);
});

test('la URL apunta a attack.mitre.org', () => {
  assert.equal(techniqueFor('links.ip').url, 'https://attack.mitre.org/techniques/T1566/002/');
});

test('finding() añade la técnica', () => {
  const f = finding({ id: 'links.ip', detector: 'links', severity: 'high', title: 't', detail: 'd' });
  assert.equal(f.mitre.id, 'T1566.002');
});

test('el informe resume las técnicas sin repetir', () => {
  const r = analyzeInput({ kind: 'url', value: 'http://192.168.0.1/paypal/login' });
  assert.deepEqual(r.techniques.map((t) => t.id), ['T1566.002']);
});
