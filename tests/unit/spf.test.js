import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseEml } from '../../src/parser/eml.js';
import { evaluateSpfRecord, originIp } from '../../src/auth/spf.js';

test('ip4 con CIDR y -all', () => {
  assert.deepEqual(evaluateSpfRecord('v=spf1 ip4:192.0.2.0/24 -all', '192.0.2.25'), { result: 'pass', mechanism: 'ip4:192.0.2.0/24', needs: [] });
  assert.deepEqual(evaluateSpfRecord('v=spf1 ip4:192.0.2.0/24 -all', '198.51.100.1'), { result: 'fail', mechanism: '-all', needs: [] });
});

test('calificadores ~ y ?', () => {
  assert.equal(evaluateSpfRecord('v=spf1 ip4:192.0.2.1 ~all', '203.0.113.5').result, 'softfail');
  assert.equal(evaluateSpfRecord('v=spf1 ?all', '203.0.113.5').result, 'neutral');
  assert.equal(evaluateSpfRecord('v=spf1 -ip4:203.0.113.5 +all', '203.0.113.5').result, 'fail');
});

test('un mecanismo que necesita DNS antes del acierto lo hace no verificable', () => {
  assert.deepEqual(evaluateSpfRecord('v=spf1 include:_spf.google.com ip4:192.0.2.0/24 -all', '203.0.113.5'),
    { result: 'unverifiable', mechanism: null, needs: ['include:_spf.google.com'] });
  assert.equal(evaluateSpfRecord('v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all', '192.0.2.9').result, 'pass');
  assert.deepEqual(evaluateSpfRecord('v=spf1 a mx redirect=_spf.x.test', '203.0.113.5').needs, ['a', 'mx', 'redirect=_spf.x.test']);
});

test('IPv6', () => {
  assert.equal(evaluateSpfRecord('v=spf1 ip6:2001:db8::/32 -all', '2001:db8:1::25').result, 'pass');
  assert.equal(evaluateSpfRecord('v=spf1 ip6:2001:db8::/32 -all', '2001:dead::1').result, 'fail');
});

test('registros inválidos', () => {
  assert.equal(evaluateSpfRecord('ip4:1.2.3.4 -all', '1.2.3.4').result, 'permerror');
  assert.equal(evaluateSpfRecord('v=spf1 ip4:999.1.1.1 -all', '1.2.3.4').result, 'permerror');
  assert.equal(evaluateSpfRecord('v=spf1 -all', 'no-es-ip').result, 'permerror');
});

test('sin all ni acierto es neutral', () => {
  assert.equal(evaluateSpfRecord('v=spf1 ip4:192.0.2.1', '203.0.113.5').result, 'neutral');
});

test('IP de origen: la que vio el receptor (muestra 01)', () => {
  const email = parseEml(readFileSync(new URL('../../samples/01-legitimo-newsletter.eml', import.meta.url), 'utf8'));
  assert.equal(originIp(email), '192.0.2.25');
  assert.equal(originIp(parseEml('From: a@b.test\r\n\r\nx')), null);
});
