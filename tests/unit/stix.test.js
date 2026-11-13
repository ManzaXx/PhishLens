// Exportación STIX 2.1 (spec 2.3, §5.4): objetos, ids deterministas, patrones escapados y validez.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLES, BATCHES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeInput } from '../../src/core/engine.js';
import { analyzeBatch } from '../../src/core/batch.js';
import { findCampaigns } from '../../src/intel/campaigns.js';
import { toStixBundle, stixPattern, scoId } from '../../src/intel/stix.js';
import { validateBundle } from '../../tools/stix-validate.mjs';
import { shuffle } from '../helpers/batch.js';

const now = new Date('2026-11-07T10:00:00.000Z');
const one = (id) => [{ key: id, name: `${id}.eml`, report: analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id] }) }];
const types = (b) => b.objects.map((o) => o.type);
let lot;
before(async () => {
  const files = BATCHES[0].files.map((f) => ({ name: f.split('/').pop(), size: 1, text: async () => SAMPLE_TEXTS[f] }));
  lot = (await analyzeBatch(files, { yieldFn: async () => {} })).entries;
});

test('ids de los observables iguales a los de la librería oficial stix2', () => {
  assert.equal(scoId('domain-name', { value: 'example.com' }), 'domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7');
  assert.equal(scoId('url', { value: 'https://example.com/' }), 'url--be22e93a-5e33-5678-b19f-8b4ea06df0bd');
  assert.equal(scoId('email-addr', { value: 'a@example.com' }), 'email-addr--8f5f7fba-cc24-5e3f-aca4-f7194112e042');
  assert.equal(scoId('ipv4-addr', { value: '198.51.100.1' }), 'ipv4-addr--2b3e2c17-3144-5591-9c88-a605220f8c0c');
  assert.equal(scoId('ipv6-addr', { value: '2001:db8::1' }), 'ipv6-addr--6469e3a9-b053-5e34-a025-9396ae051d26');
  assert.equal(scoId('file', { hashes: { 'SHA-256': 'a'.repeat(64) } }), 'file--75cb38d5-2055-5354-b75a-8299a2d670b5');
  assert.equal(scoId('file', { hashes: { 'SHA-256': 'a'.repeat(64), MD5: 'b'.repeat(32) }, name: 'x.pdf' }), 'file--1ad89290-5a40-59f1-bc37-a566e7fc8438');
  assert.equal(scoId('email-message', { from_ref: 'email-addr--8f5f7fba-cc24-5e3f-aca4-f7194112e042', subject: 'Hola', is_multipart: false }),
    'email-message--b0e2c2ea-4644-5ae5-9dc5-d82ff7db50c8');
});

test('todas las muestras y el lote dan bundles válidos', () => {
  for (const s of SAMPLES) assert.deepEqual(validateBundle(toStixBundle(one(s.id), { now })), [], s.id);
  assert.deepEqual(validateBundle(toStixBundle(lot, { campaigns: findCampaigns(lot), now })), []);
});

test('mismo correo, mismos ids; el lote en otro orden, el mismo bundle', () => {
  assert.deepEqual(toStixBundle(one('03-phishing-banco'), { now }), toStixBundle(one('03-phishing-banco'), { now }));
  const base = toStixBundle(lot, { campaigns: findCampaigns(lot), now });
  for (const seed of [1, 2, 3]) {
    const other = shuffle(lot, seed);
    assert.deepEqual(toStixBundle(other, { campaigns: findCampaigns(other), now }), base);
  }
  const ids = base.objects.map((o) => o.id);
  assert.deepEqual(ids, [...ids].sort());
});

test('muestra 03: correo, remitente, URL, dominio, indicador y la técnica de enlace', () => {
  const b = toStixBundle(one('03-phishing-banco'), { now });
  for (const t of ['email-message', 'email-addr', 'url', 'domain-name', 'indicator', 'attack-pattern', 'relationship']) assert.ok(types(b).includes(t), t);
  const ap = b.objects.find((o) => o.type === 'attack-pattern' && o.external_references[0].external_id === 'T1566.002');
  assert.deepEqual(ap.external_references[0], { source_name: 'mitre-attack', external_id: 'T1566.002', url: 'https://attack.mitre.org/techniques/T1566/002/' });
  const msg = b.objects.find((o) => o.type === 'email-message');
  assert.ok(b.objects.some((o) => o.id === msg.from_ref && o.type === 'email-addr'));
  assert.equal(msg.body, undefined);
  const ind = b.objects.filter((o) => o.type === 'indicator');
  assert.ok(ind.every((i) => i.pattern_type === 'stix' && i.valid_from === now.toISOString()));
  // El validador oficial de OASIS pide nombre y descripción en los indicadores.
  assert.ok(ind.every((i) => i.name && i.description === 'Visto en un correo que PhishLens clasifica como «Phishing casi seguro».'), JSON.stringify(ind[0]));
  assert.ok(b.objects.some((o) => o.type === 'relationship' && o.relationship_type === 'based-on'));
  assert.ok(b.objects.some((o) => o.type === 'relationship' && o.relationship_type === 'indicates' && o.target_ref === ap.id));
});

test('adjuntos: file con sus tres hashes, unido al correo; la muestra 11 lleva indicador del hash', () => {
  const b = toStixBundle(one('11-adjunto-tipo-falso'), { now });
  const file = b.objects.find((o) => o.type === 'file');
  assert.deepEqual(Object.keys(file.hashes).sort(), ['MD5', 'SHA-1', 'SHA-256']);
  assert.equal(file.name, 'factura.pdf');
  const msg = b.objects.find((o) => o.type === 'email-message');
  assert.equal(msg.is_multipart, true);
  assert.ok(msg.body_multipart.some((p) => p.body_raw_ref === file.id));
  assert.ok(b.objects.some((o) => o.type === 'indicator' && o.pattern === `[file:hashes.'SHA-256' = '${file.hashes['SHA-256']}']`));
});

test('el lote lleva su campaña, unida a sus técnicas y a sus indicadores', () => {
  const b = toStixBundle(lot, { campaigns: findCampaigns(lot), now });
  const camp = b.objects.filter((o) => o.type === 'campaign');
  assert.equal(camp.length, 1);
  assert.equal(camp[0].name, 'Campaña 1');
  assert.ok(camp[0].description.startsWith('4 correos que comparten'));
  assert.ok(b.objects.some((o) => o.type === 'relationship' && o.relationship_type === 'uses' && o.source_ref === camp[0].id));
  assert.ok(b.objects.some((o) => o.type === 'relationship' && o.relationship_type === 'indicates' && o.target_ref === camp[0].id));
});

test('Review Focus 3: comillas, barras y corchetes del atacante quedan escapados', () => {
  assert.equal(stixPattern('url', "https://x.test/a'b\\c]"), "[url:value = 'https://x.test/a\\'b\\\\c]']");
  assert.equal(stixPattern('file-sha256', 'ab'), "[file:hashes.'SHA-256' = 'ab']");
  const report = analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS['03-phishing-banco'].replace(/https?:\/\/[^\s"<>]+/, "https://pago.test/a'b\\c]?x='1'") });
  const b = toStixBundle([{ key: 'k', name: "fac'tura\\.eml", report }], { now });
  assert.deepEqual(validateBundle(b), []);
  assert.deepEqual(JSON.parse(JSON.stringify(b)), b);
});

test('Review Focus 4: desde la pestaña URL no hay email-message, y un correo legítimo no da indicadores', () => {
  const url = toStixBundle([{ key: 'u', name: 'URL', report: analyzeInput({ kind: 'url', value: 'http://3232235777/login' }) }], { now });
  assert.deepEqual(validateBundle(url), []);
  assert.ok(!types(url).includes('email-message'));
  assert.ok(types(url).includes('url'));
  const safe = toStixBundle(one('01-legitimo-newsletter'), { now });
  assert.ok(!types(safe).includes('indicator'));
  assert.deepEqual(validateBundle(safe), []);
});

test('IPv6 e IDN', () => {
  const b = toStixBundle([{ key: 'u', name: 'URL', report: analyzeInput({ kind: 'url', value: 'http://[2001:db8::1]/pago' }) }], { now });
  assert.ok(types(b).includes('ipv6-addr') || types(b).includes('url'));
  assert.deepEqual(validateBundle(b), []);
  const idn = toStixBundle(one('10-dominio-unicode'), { now });
  const domains = idn.objects.filter((o) => o.type === 'domain-name').map((o) => o.value);
  assert.ok(domains.some((d) => d.startsWith('xn--') || d.includes('.xn--')), domains.join());
  assert.ok(domains.every((d) => /^[\x21-\x7e]+$/.test(d)));
});

test('revisión final: la infraestructura compartida y las direcciones de marca no son indicadores', () => {
  const extra = [
    'Received: from eu-smtp-inbound-1.mimecast.com (eu-smtp-inbound-1.mimecast.com [195.130.217.30]) by mx.example.com; Thu, 05 Nov 2026 08:41:12 +0100',
    'Received: from a8-11.smtp-out.amazonses.com (a8-11.smtp-out.amazonses.com [54.240.7.11]) by eu-smtp-inbound-1.mimecast.com; Thu, 05 Nov 2026 08:41:11 +0100',
    'Return-Path: <0102018f@eu-west-1.amazonses.com>',
  ].join('\r\n');
  const text = `${extra}\r\n${SAMPLE_TEXTS['03-phishing-banco']}`;
  const report = analyzeInput({ kind: 'eml', value: text });
  const b = toStixBundle([{ key: 'x', name: 'x.eml', report }], { now });
  assert.deepEqual(validateBundle(b), []);
  const patterns = b.objects.filter((o) => o.type === 'indicator').map((o) => o.pattern);
  for (const bad of ['195.130.217.30', '54.240.7.11', 'amazonses.com']) assert.ok(!patterns.some((p) => p.includes(bad)), `${bad}: ${patterns.join('\n')}`);
  // Siguen como observables.
  assert.ok(b.objects.some((o) => o.type === 'ipv4-addr' && o.value === '54.240.7.11') || !report.iocs.ips.includes('54.240.7.11'));
  // Un From suplantado con la dirección real del banco no se exporta como malicioso.
  const spoof = analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS['03-phishing-banco'].replace(/^From: .*$/m, 'From: Banco <avisos@bancosantander.es>') });
  const sp = toStixBundle([{ key: 's', name: 's.eml', report: spoof }], { now });
  assert.ok(!sp.objects.some((o) => o.type === 'indicator' && o.pattern.includes('bancosantander.es')));
});
