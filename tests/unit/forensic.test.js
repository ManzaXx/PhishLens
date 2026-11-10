// Informe forense (spec 3.0, §4): contenido en orden, hashes que coinciden con sha256sum y JSON verificable.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { analyzeInput } from '../../src/core/engine.js';
import { forensicReport, forensicJson, verifyForensicJson, forensicFileName, MAX_NOTES, LIMITS_TEXT } from '../../src/intel/forensic.js';

const file = (id) => new URL(`../../samples/${id}.eml`, import.meta.url);
const textOf = (id) => readFileSync(file(id), 'utf8');
const hash = (alg, data) => createHash(alg).update(data).digest('hex');
const AT = new Date('2026-11-10T12:34:56Z');
const live = (id, extra = {}) => {
  const text = textOf(id);
  return forensicReport({ report: analyzeInput({ kind: 'eml', value: text }), source: { kind: 'live', name: `${id}.eml`, text }, analyzedAt: AT, version: '2.3.0', notes: '', ...extra });
};

test('identificación en vivo: nombre, tamaño en bytes UTF-8, SHA-256/SHA-1/MD5 y fechas UTC y local', () => {
  const doc = live('03-phishing-banco');
  const bytes = readFileSync(file('03-phishing-banco'));
  const id = doc.identification;
  assert.equal(id.name, '03-phishing-banco.eml');
  assert.equal(id.sha256, hash('sha256', bytes));
  assert.equal(id.sha1, hash('sha1', bytes));
  assert.equal(id.md5, hash('md5', bytes));
  assert.equal(id.size, bytes.length);
  assert.equal(id.analyzedAt.utc, '2026-11-10T12:34:56.000Z');
  assert.ok(id.analyzedAt.local.length > 0);
  assert.equal(id.version, '2.3.0');
  assert.equal(id.savedAt, null);
  assert.deepEqual(Object.keys(doc), ['tool', 'format', 'identification', 'verdict', 'findings', 'auth', 'timeline', 'iocs', 'attachments', 'urls', 'notes', 'limits']);
});

test('Review Focus 4: CRLF y no ASCII: el SHA-256 es el de los bytes UTF-8', () => {
  const text = textOf('03-phishing-banco').replace('Subject:', 'Subject: año').replaceAll('\n', '\r\n');
  const doc = forensicReport({ report: analyzeInput({ kind: 'eml', value: text }), source: { kind: 'live', name: 'x.eml', text }, analyzedAt: AT, version: '2.3.0', notes: '' });
  assert.equal(doc.identification.sha256, hash('sha256', Buffer.from(text, 'utf8')));
  assert.equal(doc.identification.md5, hash('md5', Buffer.from(text, 'utf8')));
  assert.equal(doc.identification.size, Buffer.byteLength(text));
});

test('desde el historial: SHA-256 guardado, savedAt, y SHA-1, MD5 y tamaño null', () => {
  const report = analyzeInput({ kind: 'eml', value: textOf('03-phishing-banco') });
  const doc = forensicReport({ report, source: { kind: 'saved', name: 'x.eml', sha256: 'a'.repeat(64), savedAt: '2026-11-01T10:00:00.000Z' }, analyzedAt: new Date('2026-11-01T10:00:00Z'), version: '2.3.0', notes: '' });
  assert.equal(doc.identification.sha256, 'a'.repeat(64));
  assert.equal(doc.identification.savedAt, '2026-11-01T10:00:00.000Z');
  assert.equal(doc.identification.sha1, null);
  assert.equal(doc.identification.md5, null);
  assert.equal(doc.identification.size, null);
});

test('veredicto: nivel, etiqueta, puntuación, confianza y la frase del modo sencillo', () => {
  const text = textOf('03-phishing-banco');
  const report = analyzeInput({ kind: 'eml', value: text });
  const { verdict } = live('03-phishing-banco');
  assert.deepEqual(verdict, { level: report.level, label: report.label, score: report.score, confidence: report.confidence.level, headline: report.verdict.headline });
});

test('hallazgos por gravedad, estables dentro de cada gravedad, con evidencia defanged y técnica', () => {
  const report = analyzeInput({ kind: 'eml', value: textOf('07-phishing-avanzado') });
  report.findings.push({ id: 'x.test', severity: 'low', title: 'Prueba', detail: '', evidence: 'http://evil.test/x', mitre: null, techniques: [] });
  const doc = forensicReport({ report, source: { kind: 'live', name: null, text: 'x' }, analyzedAt: AT, version: '2.3.0', notes: '' });
  const order = ['high', 'medium', 'low', 'info'];
  const ranks = doc.findings.map((f) => order.indexOf(f.severity));
  assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b));
  const sameSeverity = report.findings.filter((f) => f.severity === 'high').map((f) => f.id);
  assert.deepEqual(doc.findings.filter((f) => f.severity === 'high').map((f) => f.id), sameSeverity);
  assert.equal(doc.findings.find((f) => f.id === 'x.test').evidence, 'hxxp://evil[.]test/x');
  const withTech = doc.findings.find((f) => f.technique);
  assert.match(withTech.technique, /^T\d{4}/);
});

test('autenticación: spf, dkim y dmarc con su state, result y detail', () => {
  const { auth } = live('03-phishing-banco');
  for (const k of ['spf', 'dkim', 'dmarc']) {
    assert.deepEqual(Object.keys(auth[k]), ['state', 'result', 'detail'], k);
    assert.equal(typeof auth[k].state, 'string');
  }
});

test('cronología: fecha del correo y saltos en orden de llegada, marcando los que van atrás en el tiempo', () => {
  const { timeline } = live('08-ruta-falsificada');
  assert.equal(timeline.date, 'Wed, 21 Oct 2026 08:30:00 +0200');
  assert.ok(timeline.hops.length >= 2);
  assert.equal(timeline.hops[0].backwards, false);
  assert.ok(timeline.hops.some((h) => h.backwards));
  for (const h of timeline.hops) assert.deepEqual(Object.keys(h), ['from', 'by', 'ip', 'date', 'utc', 'backwards']);
});

test('IOCs agrupados por tipo y defanged, sin grupos vacíos', () => {
  const { iocs } = live('03-phishing-banco');
  assert.ok(iocs.length > 0);
  for (const g of iocs) {
    assert.ok(g.items.length > 0, g.type);
    assert.equal(typeof g.label, 'string');
  }
  const domains = iocs.find((g) => g.type === 'domains');
  assert.ok(domains.items.every((d) => d.includes('[.]')));
});

test('adjuntos: nombre, tipo declarado y real, tamaño, tres hashes y lo visto por dentro', () => {
  const { attachments } = live('12-pdf-activo-zip');
  const pdf = attachments.find((a) => a.name === 'aviso.pdf');
  assert.equal(pdf.declaredType, 'application/pdf');
  assert.equal(pdf.realType, 'PDF');
  assert.equal(pdf.size, 246);
  assert.match(pdf.sha256, /^[0-9a-f]{64}$/);
  assert.match(pdf.sha1, /^[0-9a-f]{40}$/);
  assert.match(pdf.md5, /^[0-9a-f]{32}$/);
  assert.match(pdf.seen, /JavaScript/);
});

test('URLs: una por href distinto, con su cadena defanged y el aviso de tope', () => {
  const { urls } = live('13-redireccion-anidada');
  assert.ok(urls.items.length > 0);
  assert.ok(urls.items.every((u) => !/https?:\/\//.test(u.chain)), 'defanged');
  const report = analyzeInput({ kind: 'eml', value: textOf('03-phishing-banco') });
  report.email.links = Array.from({ length: 150 }, (_, i) => ({ href: `https://h${i}.test/` }));
  const doc = forensicReport({ report, source: { kind: 'live', name: null, text: 'x' }, analyzedAt: AT, version: '2.3.0', notes: '' });
  assert.equal(doc.urls.items.length, 100);
  assert.equal(doc.urls.total, 150);
});

test('Review Focus 3: URL suelta y texto pegado sin Received no lanzan; listas vacías y name null', () => {
  for (const input of [{ kind: 'url', value: 'https://login-banco.test/x' }, { kind: 'text', value: 'Hola, pulsa aquí' }]) {
    const doc = forensicReport({ report: analyzeInput(input), source: { kind: 'live', name: null, text: input.value }, analyzedAt: AT, version: '2.3.0', notes: '' });
    assert.equal(doc.identification.name, null);
    assert.deepEqual(doc.timeline.hops, []);
    assert.deepEqual(doc.attachments, []);
    assert.ok(Array.isArray(doc.findings));
  }
});

test('Review Focus 2: notas recortadas a 5000; solo espacios → null', () => {
  assert.equal(MAX_NOTES, 5000);
  assert.equal(live('03-phishing-banco', { notes: 'x'.repeat(5001) }).notes.length, 5000);
  assert.equal(live('03-phishing-banco', { notes: '  \n\t ' }).notes, null);
  assert.equal(live('03-phishing-banco', { notes: '<script>a</script>' }).notes, '<script>a</script>');
});

test('límites: la línea fija nombra DNS, reputación y flujos PDF comprimidos, y docs/limitations.md como texto', () => {
  assert.equal(live('03-phishing-banco').limits, LIMITS_TEXT);
  for (const w of ['DNS', 'reputación', 'flujos', 'PDF', 'docs/limitations.md']) assert.ok(LIMITS_TEXT.includes(w), w);
});

test('integridad: verifyForensicJson acepta lo de forensicJson y rechaza cambios, sin campo o no JSON', () => {
  const json = forensicJson(live('03-phishing-banco', { notes: 'nota' }));
  const parsed = JSON.parse(json);
  assert.equal(Object.keys(parsed).at(-1), 'reportSha256');
  assert.equal(verifyForensicJson(json), true);
  assert.equal(verifyForensicJson(json.replace('nota', 'note')), false);
  const { reportSha256, ...rest } = parsed;
  assert.match(reportSha256, /^[0-9a-f]{64}$/);
  assert.equal(reportSha256, hash('sha256', JSON.stringify(rest, null, 2)));
  assert.equal(verifyForensicJson(JSON.stringify(rest, null, 2)), false);
  assert.equal(verifyForensicJson('no es json'), false);
  assert.equal(verifyForensicJson('null'), false);
});

test('nombre del fichero con la fecha en UTC', () => {
  assert.equal(forensicFileName(new Date('2026-11-10T23:30:00Z')), 'phishlens-forense-2026-11-10.json');
});
