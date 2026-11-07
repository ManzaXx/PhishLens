// Historial (spec 3.0, §2.2 y §6): informe recortado sin el correo y validador de lo que viene de fuera.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SAMPLES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeInput } from '../../src/core/engine.js';
import { slimReport, validateEntry, safeParse } from '../../src/storage/schema.js';
import { rng, pick } from '../helpers/rng.js';

const report = (id) => analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id] });
const entryOf = (r, extra = {}) => ({
  id: '3b241101-e2bb-4255-8caf-4136c566a962', savedAt: '2026-11-07T10:00:00.000Z', version: '2.3.0',
  kind: 'eml', sha256: 'a'.repeat(64), name: 'x.eml', report: slimReport(r), ...extra,
});

test('slimReport quita el cuerpo y conserva lo que necesita el analista', () => {
  for (const s of SAMPLES) {
    const r = report(s.id);
    const before = structuredClone(r);
    const slim = slimReport(r);
    assert.deepEqual(r, before, `${s.id}: no debe tocar el original`);
    assert.equal(slim.email.text, undefined, s.id);
    assert.equal(slim.email.html, undefined, s.id);
    assert.deepEqual(slim.findings.map((f) => f.id), r.findings.map((f) => f.id));
    assert.deepEqual(slim.iocs, r.iocs);
    assert.deepEqual(slim.techniques, r.techniques);
    assert.deepEqual(slim.email.links, r.email.links);
    assert.deepEqual(slim.email.route, r.email.route);
    for (const [i, a] of (r.email.attachments ?? []).entries()) {
      assert.equal(slim.email.attachments[i].sha256, a.sha256);
      assert.equal(slim.email.attachments[i].bytes, undefined);
    }
  }
});

const WORDS = ['urgente', 'cuenta', 'factura', 'pago', 'hoy', 'confirme', 'datos', 'acceso', 'bloqueada', 'cliente', 'estimado', 'banco', 'verifique', 'inmediato', 'premio', 'gratis'];
test('propiedad: ningún trozo de 41 caracteres del cuerpo sobrevive en el informe recortado', () => {
  const r = rng(3001);
  for (let n = 0; n < 200; n++) {
    const sentence = () => Array.from({ length: 6 + pick(r, 10) }, () => WORDS[pick(r, WORDS.length)]).join(' ');
    const text = Array.from({ length: 3 + pick(r, 5) }, sentence).join('. ');
    const html = pick(r, 2) ? `<p>${sentence()}</p><form action="x"><p>${sentence()}</p></form>` : '';
    const raw = ['From: Banco <avisos@banco-falso.test>', 'To: a@b.test', `Subject: Aviso ${n}`,
      html ? 'Content-Type: text/html; charset=utf-8' : 'Content-Type: text/plain; charset=utf-8', '', html || text].join('\r\n');
    const full = analyzeInput({ kind: 'eml', value: raw });
    const body = `${full.email.text ?? ''}\n${full.email.html ?? ''}`;
    const json = JSON.stringify(slimReport(full));
    for (let i = 0; i + 41 <= body.length; i += 7) {
      const chunk = body.slice(i, i + 41);
      assert.ok(!json.includes(chunk), `semilla ${n}: «${chunk}»`);
    }
  }
});

test('validateEntry acepta una entrada buena y rechaza cada campo malo nombrándolo', () => {
  const r = report('03-phishing-banco');
  const ok = validateEntry(entryOf(r));
  assert.equal(ok.ok, true);
  const cases = [
    [{ kind: 'headers' }, 'kind'],
    [{ sha256: 'a'.repeat(63) }, 'sha256'],
    [{ name: 'x'.repeat(300) }, 'name'],
    [{ id: 'no-es-uuid' }, 'id'],
    [{ savedAt: 'ayer' }, 'savedAt'],
    [{ version: 'v2' }, 'version'],
  ];
  for (const [extra, field] of cases) {
    const res = validateEntry(entryOf(r, extra));
    assert.equal(res.ok, false, field);
    assert.match(res.error, new RegExp(field), field);
  }
  const bad = entryOf(r);
  bad.report = { ...bad.report, level: 'pwned' };
  assert.match(validateEntry(bad).error, /level/);
  const big = entryOf(r);
  big.report = { ...big.report, summary: 'x'.repeat(2 * 1024 * 1024) };
  assert.equal(validateEntry(big).ok, false);
  assert.equal(validateEntry(null).ok, false);
  assert.equal(validateEntry([]).ok, false);
});

test('Review Focus 2: entradas manipuladas no contaminan ni pasan', () => {
  const r = report('03-phishing-banco');
  const text = JSON.stringify(entryOf(r)).replace('{', '{"__proto__":{"polluted":1},"constructor":{"prototype":{"x":1}},');
  const parsed = safeParse(text);
  const res = validateEntry(parsed);
  assert.equal(res.ok, true);
  assert.equal(({}).polluted, undefined);
  assert.equal(({}).x, undefined);
  assert.equal(Object.hasOwn(res.entry, '__proto__'), false);
  const huge = entryOf(r);
  huge.report = structuredClone(huge.report);
  huge.report.findings[0].title = 'x'.repeat(10 * 1024 * 1024);
  assert.equal(validateEntry(huge).ok, false);
  const good = entryOf(r);
  const out = validateEntry(good).entry;
  assert.notEqual(out, good);
  assert.notEqual(out.report, good.report);
  assert.throws(() => safeParse('{no'));
});
