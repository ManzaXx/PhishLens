import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adviceFor } from '../src/advice.js';

const report = (level, ids) => ({ level, findings: ids.map((id) => ({ id, points: 15 })) });

test('consejos para phishing incluyen no hacer clic y reportar', () => {
  const a = adviceFor(report('phishing', ['links.mismatch']));
  assert.ok(a.some((x) => /No pulses/.test(x)));
  assert.ok(a.some((x) => /017/.test(x)));
});
test('si pide credenciales: cambia la contraseña', () => {
  assert.ok(adviceFor(report('phishing', ['language.credentials'])).some((x) => /cambia/i.test(x)));
});
test('si hay adjunto peligroso: no lo abras', () => {
  assert.ok(adviceFor(report('suspicious', ['attachments.double-extension'])).some((x) => /adjunto/i.test(x)));
});
test('si suplanta una marca: contacta por el canal oficial', () => {
  assert.ok(adviceFor(report('suspicious', ['sender.brand-impersonation'])).some((x) => /oficial/i.test(x)));
});
test('legítimo: consejo prudente, sin alarmas', () => {
  const a = adviceFor(report('safe', []));
  assert.equal(a.length, 1);
  assert.match(a[0], /no garantiza/i);
});
