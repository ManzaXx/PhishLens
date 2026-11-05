import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseEml } from '../../src/parser/eml.js';
import { parseHop, parseRoute, receivingHop } from '../../src/parser/received.js';
import { receivingHop as fromTrust } from '../../src/auth/trust.js';

const sample = (name) => parseEml(readFileSync(new URL(`../../samples/${name}.eml`, import.meta.url), 'utf8'));

test('parseHop separa HELO, rDNS, IP y hora UTC', () => {
  const hop = parseHop('from vps-4471.hosting-barato.test (unknown [203.0.113.66]) by mx.example.com; Wed, 21 Oct 2026 07:03:04 +0200');
  assert.equal(hop.helo, 'vps-4471.hosting-barato.test');
  assert.equal(hop.from, 'vps-4471.hosting-barato.test');
  assert.equal(hop.rdns, 'unknown');
  assert.equal(hop.ip, '203.0.113.66');
  assert.equal(hop.by, 'mx.example.com');
  assert.equal(hop.time, Date.UTC(2026, 9, 21, 5, 3, 4));
  assert.match(hop.raw, /^from vps-4471/);
});

test('fecha ilegible o con comentario', () => {
  assert.equal(parseHop('from a by b; no es una fecha').time, null);
  assert.equal(parseHop('from a by b; Wed, 21 Oct 2026 07:03:04 +0200 (CEST)').time, Date.UTC(2026, 9, 21, 5, 3, 4));
});

test('parseRoute: orden de llegada y salto de entrada al receptor (muestra 01)', () => {
  const route = parseRoute(sample('01-legitimo-newsletter'));
  assert.equal(route.hops.length, 1);
  assert.equal(route.firstExternal, 0);
  assert.equal(route.hops[0].rdns, 'mail.aerovelo.example');
  assert.equal(route.parsed, 1);
});

test('parseRoute: muestra 03 entra por el salto del VPS', () => {
  const route = parseRoute(sample('03-phishing-banco'));
  assert.equal(route.hops.length, 2);
  assert.equal(route.hops[route.firstExternal].helo, 'vps-4471.hosting-barato.test');
  assert.equal(route.hops[0].by, 'vps-4471.hosting-barato.test');
});

test('sin Received no hay salto de entrada', () => {
  const route = parseRoute(parseEml('From: a@b.test\n\nhola'));
  assert.deepEqual([route.hops.length, route.firstExternal, route.parsed], [0, null, 0]);
});

test('receivingHop vive en parser y auth/trust lo reexporta', () => {
  assert.equal(fromTrust, receivingHop);
});
