// Motor de reglas propias (spec 3.0, §5.1 y §5.2): campos con un mapa explícito, operadores cerrados,
// NFKC y minúsculas, y hallazgos «custom.<id>» que nunca bajan la nota.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { parseEml } from '../../src/parser/eml.js';
import { analyzeInput } from '../../src/core/engine.js';
import { validateRules, FIELD_NAMES, OPERATORS, LIST_FIELDS } from '../../src/rules/validate.js';
import { FIELDS, evaluate, customFindings } from '../../src/rules/evaluate.js';
import { rng, pick } from '../helpers/rng.js';
import { installDom, find } from '../helpers/dom.js';

const email = (id) => parseEml(SAMPLE_TEXTS[id]);
const prior = (id) => analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id] }).findings;
const EXAMPLE = readFileSync(new URL('../../samples/rules/ejemplo.json', import.meta.url), 'utf8');
const rulesOf = (when, extra = {}) => {
  const out = validateRules(JSON.stringify({ phishlens: 'rules/1', rules: [{ id: 'prueba', title: 'Prueba', severity: 'medium', category: 'sender', when, ...extra }] }));
  assert.equal(out.ok, true, JSON.stringify(out.errors));
  return out.rules;
};
const matches = (id, when) => evaluate(rulesOf(when)[0], email(id), prior(id)).match;
const c = (field, op, value) => (value === undefined ? { field, op } : { field, op, value });

test('FIELDS cubre exactamente los campos admitidos y es un Map', () => {
  assert.ok(FIELDS instanceof Map);
  assert.deepEqual([...FIELDS.keys()].sort(), [...FIELD_NAMES].sort());
});

test('campos: lo que lee cada uno en las muestras 03 y 12', () => {
  const e3 = email('03-phishing-banco');
  const p3 = prior('03-phishing-banco');
  const read = (f, e = e3, p = p3) => FIELDS.get(f)(e, p);
  assert.equal(read('subject'), 'Último aviso: su cuenta ha sido bloqueada');
  assert.equal(read('sender.address'), 'avisos@santander-seguridad.test');
  assert.equal(read('sender.domain'), 'santander-seguridad.test');
  assert.equal(read('sender.display'), 'Banco Santander');
  assert.equal(read('reply-to.domain'), 'correo-rapido.test');
  assert.equal(read('return-path.domain'), 'mailer-masivo.test');
  assert.deepEqual(read('link.domain'), ['santander-seguridad.test']);
  assert.deepEqual(read('link.url'), ['http://santander-seguridad.test/acceso/login.php']);
  assert.match(read('header:x-mailer')[0], /^PHPMailer 6\.8\.1/);
  assert.ok(read('finding.id').includes('lookalike.brand-in-domain'));
  assert.ok(read('body.text').length > 0);
  const e12 = email('12-pdf-activo-zip');
  assert.deepEqual(read('attachment.name', e12), ['aviso.pdf', 'documentos.zip']);
  assert.deepEqual(read('attachment.extension', e12), ['pdf', 'zip']);
  assert.deepEqual(read('attachment.type', e12), ['application/pdf', 'application/zip']);
  for (const h of read('attachment.sha256', e12)) assert.match(h, /^[0-9a-f]{64}$/);
});

test('operadores sobre texto: equals, contains, starts-with y ends-with', () => {
  const id = '03-phishing-banco';
  assert.equal(matches(id, c('sender.domain', 'equals', 'SANTANDER-seguridad.test')), true);
  assert.equal(matches(id, c('sender.domain', 'equals', 'santander')), false);
  assert.equal(matches(id, c('subject', 'contains', 'CUENTA')), true);
  assert.equal(matches(id, c('subject', 'contains', 'factura')), false);
  assert.equal(matches(id, c('sender.address', 'starts-with', 'avisos@')), true);
  assert.equal(matches(id, c('sender.address', 'starts-with', 'seguridad')), false);
  assert.equal(matches(id, c('sender.domain', 'ends-with', '.test')), true);
  assert.equal(matches(id, c('sender.domain', 'ends-with', '.es')), false);
});

test('in, not-in y exists, también sobre listas («algún elemento cumple»)', () => {
  const id = '12-pdf-activo-zip';
  assert.equal(matches(id, c('attachment.extension', 'in', ['zip', 'rar'])), true);
  assert.equal(matches(id, c('attachment.extension', 'in', ['exe'])), false);
  assert.equal(matches(id, c('attachment.extension', 'not-in', ['pdf'])), true);
  assert.equal(matches(id, c('attachment.extension', 'not-in', ['pdf', 'zip'])), false);
  assert.equal(matches(id, c('sender.domain', 'not-in', ['otra.es'])), true);
  assert.equal(matches(id, c('reply-to.domain', 'exists')), true);
  assert.equal(matches('05-phishing-microsoft365', c('reply-to.domain', 'exists')), false);
  assert.equal(matches(id, c('attachment.name', 'exists')), true);
  assert.equal(matches(id, c('link.url', 'exists')), false);
  assert.equal(matches(id, c('header:x-mailer', 'exists')), false);
});

test('count-gte con 0, 1 y N', () => {
  assert.equal(matches('12-pdf-activo-zip', c('link.url', 'count-gte', 0)), true);
  assert.equal(matches('12-pdf-activo-zip', c('attachment.name', 'count-gte', 2)), true);
  assert.equal(matches('12-pdf-activo-zip', c('attachment.name', 'count-gte', 3)), false);
  assert.equal(matches('10-dominio-unicode', c('link.url', 'count-gte', 4)), true);
  assert.equal(matches('03-phishing-banco', c('link.url', 'count-gte', 1)), true);
});

test('all, any y not, también anidados hasta 4 niveles', () => {
  const id = '03-phishing-banco';
  const yes = c('subject', 'contains', 'cuenta');
  const no = c('subject', 'contains', 'factura');
  assert.equal(matches(id, { all: [yes, yes] }), true);
  assert.equal(matches(id, { all: [yes, no] }), false);
  assert.equal(matches(id, { any: [no, yes] }), true);
  assert.equal(matches(id, { any: [no, no] }), false);
  assert.equal(matches(id, { not: no }), true);
  assert.equal(matches(id, { not: yes }), false);
  assert.equal(matches(id, { all: [{ any: [no, { not: { all: [no] } }] }] }), true);
});

test('Review Focus 2: NFKC y mayúsculas; el RLO solo cumple con el RLO', () => {
  const text = SAMPLE_TEXTS['03-phishing-banco'].replace(/^Subject:.*$/m, 'Subject: ＦＡＣＴＵＲＡ pendiente');
  const e = parseEml(text);
  const rule = rulesOf(c('subject', 'contains', 'factura'))[0];
  assert.equal(evaluate(rule, e, []).match, true);
  assert.equal(evaluate(rulesOf(c('subject', 'contains', 'Factura'))[0], e, []).match, true);
  const rlo = SAMPLE_TEXTS['11-adjunto-tipo-falso'].replaceAll('factura.pdf', 'factura\u202Efdp.exe');
  const er = parseEml(rlo);
  assert.equal(evaluate(rulesOf(c('attachment.name', 'contains', 'facturafdp'))[0], er, []).match, false);
  assert.equal(evaluate(rulesOf(c('attachment.name', 'contains', '\u202Efdp'))[0], er, []).match, true);
});

test('Review Focus 3: URL suelta, texto sin cabeceras y correo sin adjuntos ni Reply-To no lanzan y no cumplen', () => {
  const inputs = [{ kind: 'url', value: 'https://login-banco.test/x' }, { kind: 'text', value: 'Hola, pulsa aquí' }, { kind: 'url', value: 'no es url' }];
  const conds = FIELD_NAMES.flatMap((f) => [c(f, 'exists'), c(f, 'equals', 'x'), c(f, 'not-in', ['x'])]);
  for (const input of inputs) {
    const report = analyzeInput(input);
    for (const when of conds) {
      const rule = rulesOf(when)[0];
      assert.doesNotThrow(() => evaluate(rule, input.kind === 'url' ? { links: [], attachments: [], headers: new Map(), from: null } : parseEml(input.value), report.findings));
    }
  }
  const noHeaders = parseEml('Hola, pulsa aquí');
  for (const f of ['subject', 'sender.domain', 'reply-to.domain', 'return-path.domain', 'header:x-mailer', 'attachment.name']) {
    assert.equal(evaluate(rulesOf(c(f, 'exists'))[0], noHeaders, []).match, false, f);
    assert.equal(evaluate(rulesOf(c(f, 'not-in', ['x']))[0], noHeaders, []).match, false, f);
  }
  assert.equal(matches('05-phishing-microsoft365', c('reply-to.domain', 'not-in', ['x'])), false);
});

test('finding.id ve los hallazgos de PhishLens y no los de otras reglas propias', () => {
  const rules = validateRules(JSON.stringify({ phishlens: 'rules/1', rules: [
    { id: 'primera', title: 'A', severity: 'low', category: 'sender', when: c('subject', 'exists') },
    { id: 'segunda', title: 'B', severity: 'low', category: 'sender', when: c('finding.id', 'starts-with', 'custom.') },
  ] })).rules;
  const found = customFindings(rules, email('03-phishing-banco'), prior('03-phishing-banco'));
  assert.deepEqual(found.map((f) => f.id), ['custom.primera']);
});

test('hallazgo custom: id, detector, procedencia, técnica, texto llano y marca', () => {
  const rules = rulesOf(c('subject', 'contains', 'cuenta'), { technique: 'T1566.002', detail: 'Lo que pasa.', severity: 'high', category: 'links' });
  const [f] = customFindings(rules, email('03-phishing-banco'), []);
  assert.equal(f.id, 'custom.prueba');
  assert.equal(f.detector, 'custom');
  assert.equal(f.provenance, 'declared');
  assert.equal(f.reliability, 'medium');
  assert.equal(f.severity, 'high');
  assert.equal(f.category, 'links');
  assert.equal(f.polarity, 'risk');
  assert.equal(f.custom, true);
  assert.equal(f.plain, 'Prueba');
  assert.equal(f.detail, 'Lo que pasa. Regla propia.');
  assert.equal(f.mitre.id, 'T1566.002');
  assert.deepEqual(f.techniques.map((t) => t.id), ['T1566.002']);
  assert.equal(f.evidence, 'último aviso: su cuenta ha sido bloqueada'.slice(0, 200));
  const [g] = customFindings(rulesOf(c('subject', 'exists')), email('03-phishing-banco'), []);
  assert.equal(g.detail, 'Regla propia.');
  assert.deepEqual(g.techniques, []);
  assert.equal(g.mitre, null);
});

test('analyzeInput con rules: los hallazgos custom entran en la nota; sin reglas, igual que antes', () => {
  const value = SAMPLE_TEXTS['02-legitimo-pedido'];
  const before = analyzeInput({ kind: 'eml', value });
  const same = analyzeInput({ kind: 'eml', value, rules: [] });
  assert.equal(same.score, before.score);
  const after = analyzeInput({ kind: 'eml', value, rules: rulesOf(c('sender.domain', 'equals', 'amazon.es'), { severity: 'high' }) });
  assert.ok(after.findings.some((f) => f.id === 'custom.prueba'));
  assert.ok(after.score > before.score);
});

test('golden: con las 3 reglas de ejemplo cambian solo las muestras que se esperan', () => {
  const { rules } = validateRules(EXAMPLE);
  const ids = Object.keys(SAMPLE_TEXTS).filter((k) => !k.includes('/'));
  assert.equal(ids.length, 13);
  const hit = {};
  for (const id of ids) {
    const r = analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id], rules });
    const custom = r.findings.filter((f) => f.custom).map((f) => f.id);
    if (custom.length) hit[id] = custom;
  }
  assert.deepEqual(hit, {
    '03-phishing-banco': ['custom.mi-org.suplantacion-con-enlace'],
    '04-phishing-correos': ['custom.mi-org.suplantacion-con-enlace'],
    '06-phishing-factura-adjunto': ['custom.mi-org.ejecutable-o-imagen', 'custom.mi-org.factura-falsa'],
    '10-dominio-unicode': ['custom.mi-org.suplantacion-con-enlace'],
    '11-adjunto-tipo-falso': ['custom.mi-org.factura-falsa'],
  });
});

test('Review Focus 4: una regla propia nunca baja la nota (13 muestras × 200 reglas aleatorias)', () => {
  const r = rng(20261110);
  const values = ['factura', 'cuenta', '.test', 'pdf', 'zip', 'exe', 'lookalike.', 'links.', 'santander', 'a', 'http', 'application/pdf', 'x'];
  const ids = Object.keys(SAMPLE_TEXTS).filter((k) => !k.includes('/'));
  const leaf = () => {
    const field = FIELD_NAMES[pick(r, FIELD_NAMES.length)];
    let op = OPERATORS[pick(r, OPERATORS.length)];
    if (op === 'count-gte' && !LIST_FIELDS.includes(field)) op = 'exists';
    if (op === 'exists') return c(field, op);
    if (op === 'count-gte') return c(field, op, pick(r, 3));
    if (op === 'in' || op === 'not-in') return c(field, op, [values[pick(r, values.length)], values[pick(r, values.length)]]);
    return c(field, op, values[pick(r, values.length)]);
  };
  const node = (d) => (d >= 3 || pick(r, 2) ? leaf() : pick(r, 3) === 0 ? { not: node(d + 1) } : { [pick(r, 2) ? 'all' : 'any']: [node(d + 1), node(d + 1)] });
  const rules = validateRules(JSON.stringify({ phishlens: 'rules/1', rules: Array.from({ length: 100 }, (_, i) => ({
    id: `r-${i}`, title: `R ${i}`, severity: ['low', 'medium', 'high'][pick(r, 3)], category: 'sender', when: node(0),
  })) }));
  assert.equal(rules.ok, true, JSON.stringify(rules.errors?.slice(0, 2)));
  const rules2 = rules.rules.map((x, i) => ({ ...x, id: `s-${i}`, category: ['authentication', 'links', 'attachments', 'language', 'infrastructure'][i % 5] }));
  let fired = 0;
  for (const id of ids) {
    const base = analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id] }).score;
    for (const set of [rules.rules, rules2]) {
      const out = analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS[id], rules: set });
      fired += out.findings.filter((f) => f.custom).length;
      assert.ok(out.score >= base, `${id}: ${out.score} < ${base}`);
    }
  }
  assert.ok(fired > 0);
});

test('rendimiento: 100 reglas × 20 contains sobre un cuerpo de 1 MB en menos de 300 ms', () => {
  const body = 'lorem ipsum dolor sit amet '.repeat(40000);
  const e = parseEml(`Subject: x\r\nFrom: a@b.es\r\n\r\n${body}`);
  const rules = validateRules(JSON.stringify({ phishlens: 'rules/1', rules: Array.from({ length: 100 }, (_, i) => ({
    id: `r-${i}`, title: 'R', severity: 'low', category: 'language',
    when: { all: Array.from({ length: 20 }, (_, j) => c('body.text', 'contains', `palabra-${i}-${j}`)).concat([]).slice(0, 20) },
  })) })).rules;
  assert.equal(FIELDS.get('body.text')(e, []).length, 256 * 1024, 'body.text se recorta a 256 K caracteres');
  const any = rules.map((x) => ({ ...x, when: { any: x.when.all } }));
  // El presupuesto mide el algoritmo, no al runner: una vuelta de calentamiento (JIT) y la mejor de tres,
  // porque node --test ejecuta los ficheros en paralelo y un runner compartido puede ir lento en una vuelta.
  customFindings(any, e, []);
  const ms = Math.min(...[0, 1, 2].map(() => {
    const t0 = performance.now();
    customFindings(any, e, []);
    return performance.now() - t0;
  }));
  assert.ok(ms < 300, `${ms.toFixed(0)} ms`);
});

let dom;
let findingCard;
before(async () => {
  dom = installDom();
  ({ findingCard } = await import('../../src/ui/components/finding-card.js'));
});
after(() => dom.restore());

test('findingCard pinta «Regla propia» y el título con textContent (<script> sale como texto)', () => {
  const rules = rulesOf(c('subject', 'exists'), { title: '<script>alert(1)</script>' });
  const [f] = customFindings(rules, email('03-phishing-banco'), []);
  const card = findingCard(f);
  const tag = find(card, (n) => (n.getAttribute?.('class') ?? '').includes('finding__custom'));
  assert.equal(tag.textContent, 'Regla propia');
  const title = find(card, (n) => (n.getAttribute?.('class') ?? '').includes('finding__title'));
  assert.equal(title.textContent, '<script>alert(1)</script>');
  assert.equal(find(card, (n) => (n.localName ?? n.tagName?.toLowerCase()) === 'script'), null);
});

test('revisión final: una regla sobre body.text no lleva el cuerpo a la evidencia ni al historial', async () => {
  const { slimReport } = await import('../../src/storage/schema.js');
  const secret = 'Cuenta bancaria 1234-5678-9012. Diga su PIN secreto al operador.';
  const value = `Subject: x\r\nFrom: a@b.es\r\n\r\n${secret}`;
  const rules = rulesOf({ any: [c('body.text', 'contains', 'pin'), c('body.text', 'exists')] });
  const report = analyzeInput({ kind: 'eml', value, rules });
  const f = report.findings.find((x) => x.id === 'custom.prueba');
  assert.equal(f.evidence, 'pin');
  const [g] = customFindings(rulesOf(c('body.text', 'exists')), parseEml(value), []);
  assert.ok(!g.evidence.includes('1234'), g.evidence);
  const slim = JSON.stringify(slimReport(analyzeInput({ kind: 'eml', value, rules: rulesOf(c('body.text', 'exists')) })));
  assert.ok(!slim.includes('1234-5678'), 'el cuerpo no entra en el informe recortado');
});
