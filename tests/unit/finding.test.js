import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finding, DETECTOR_DEFAULTS, CATEGORIES, RELIABILITY, PROVENANCE, POLARITY } from '../../src/core/finding.js';

const base = { id: 'x.y', title: 't', detail: 'd', severity: 'medium' };

test('valores por defecto según el detector', () => {
  const auth = finding({ ...base, id: 'auth.spf', detector: 'auth' });
  assert.equal(auth.category, 'authentication');
  assert.equal(auth.reliability, 'medium');
  assert.equal(auth.provenance, 'declared');
  assert.equal(auth.polarity, 'risk');
  const lang = finding({ ...base, detector: 'language' });
  assert.deepEqual([lang.category, lang.reliability, lang.provenance], ['language', 'low', 'inferred']);
});

test('un detector desconocido cae en infraestructura con fiabilidad baja', () => {
  const f = finding({ ...base, detector: 'plugin-externo' });
  assert.deepEqual([f.category, f.reliability, f.provenance], ['infrastructure', 'low', 'inferred']);
});

test('los valores explícitos ganan a los de por defecto', () => {
  const f = finding({ ...base, detector: 'auth', reliability: 'high', provenance: 'verified', polarity: 'trust', category: 'sender' });
  assert.deepEqual([f.category, f.reliability, f.provenance, f.polarity], ['sender', 'high', 'verified', 'trust']);
});

test('valores fuera de lista lanzan error', () => {
  assert.throws(() => finding({ ...base, detector: 'auth', reliability: 'total' }), /Fiabilidad desconocida/);
  assert.throws(() => finding({ ...base, detector: 'auth', category: 'otra' }), /Categoría desconocida/);
  assert.throws(() => finding({ ...base, detector: 'auth', provenance: 'rumor' }), /Procedencia desconocida/);
  assert.throws(() => finding({ ...base, detector: 'auth', polarity: 'neutral' }), /Polaridad desconocida/);
  assert.throws(() => finding({ ...base, detector: 'auth', severity: 'constructor' }), /Severidad desconocida/);
});

test('points, mitre y techniques', () => {
  const f = finding({ ...base, id: 'links.mismatch', detector: 'links', severity: 'high' });
  assert.equal(f.points, 30);
  assert.equal(f.mitre.id, 'T1566.002');
  assert.deepEqual(f.techniques, [f.mitre]);
  assert.deepEqual(finding({ ...base, id: 'input.no-headers', detector: 'input', severity: 'info' }).techniques, []);
});

test('ids y detectores hostiles no contaminan prototipos', () => {
  const f = finding({ ...base, id: '__proto__', detector: '__proto__' });
  assert.equal(f.category, 'infrastructure');
  assert.equal(({}).category, undefined);
  assert.equal(finding({ ...base, detector: 'constructor' }).reliability, 'low');
});

test('las listas exportadas cubren los defectos', () => {
  for (const d of Object.values(DETECTOR_DEFAULTS)) {
    assert.ok(CATEGORIES.includes(d.category));
    assert.ok(RELIABILITY.includes(d.reliability));
    assert.ok(PROVENANCE.includes(d.provenance));
  }
  assert.deepEqual(POLARITY, ['risk', 'trust']);
});

test('brand es opcional y por defecto null', () => {
  assert.equal(finding({ ...base, detector: 'sender', brand: 'PayPal' }).brand, 'PayPal');
  assert.equal(finding({ ...base, detector: 'sender' }).brand, null);
});
