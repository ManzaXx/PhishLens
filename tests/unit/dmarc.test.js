import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dmarcAlignment } from '../../src/auth/dmarc.js';

test('SPF pass de un subdominio alinea en modo relaxed', () => {
  assert.deepEqual(dmarcAlignment({ fromDomain: 'aerovelo.example', spf: { result: 'pass', domain: 'mail.aerovelo.example' }, dkim: [] }),
    { aligned: true, via: 'spf', spfAligned: true, dkimAligned: false });
});

test('DKIM pass del mismo dominio alinea', () => {
  const r = dmarcAlignment({ fromDomain: 'amazon.es', spf: null, dkim: [{ result: 'pass', domain: 'amazon.es' }] });
  assert.equal(r.aligned, true);
  assert.equal(r.via, 'dkim');
});

test('SPF pass de otro dominio no alinea', () => {
  assert.equal(dmarcAlignment({ fromDomain: 'paypal.com', spf: { result: 'pass', domain: 'mailer.test' }, dkim: [] }).aligned, false);
});

test('un DKIM fail alineado no cuenta', () => {
  const r = dmarcAlignment({ fromDomain: 'b.test', spf: null, dkim: [{ result: 'fail', domain: 'b.test' }] });
  assert.deepEqual(r, { aligned: false, via: null, spfAligned: false, dkimAligned: false });
});

test('sin dominio de From no hay alineación', () => {
  assert.equal(dmarcAlignment({ fromDomain: '', spf: { result: 'pass', domain: 'x.test' }, dkim: [] }).aligned, false);
});
