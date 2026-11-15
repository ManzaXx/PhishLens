// Franja «Qué se ha analizado» (auditoría 3.1, P9): remitente, asunto, fecha, enlaces, adjuntos y autenticación
// en una sola tarjeta, para que se vea de un vistazo a qué correo corresponde el veredicto.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installDom, find, findAll } from '../helpers/dom.js';
import { SAMPLES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';

let dom;
let analyzedStrip;
let setLang;
before(async () => {
  dom = installDom();
  ({ analyzedStrip } = await import('../../src/ui/components/analyzed-strip.js'));
  ({ setLang } = await import('../../src/i18n/index.js'));
});
after(() => dom.restore());

const sample = (prefix) => {
  const s = SAMPLES.find((x) => x.file.startsWith(prefix));
  return analyzeInput({ kind: 'eml', value: readFileSync(new URL(`../../samples/${s.file}`, import.meta.url), 'utf8') });
};
const row = (node, name) => find(node, (n) => n.getAttribute?.('data-row') === name);
const value = (node, name) => find(row(node, name), (n) => n.localName === 'dd')?.textContent;

test('muestra 03: remitente con el dominio resaltado, asunto, fecha, enlaces, adjuntos y autenticación', () => {
  const strip = analyzedStrip(sample('03'), { kind: 'eml' });
  assert.equal(strip.localName, 'section');
  assert.ok(strip.getAttribute('aria-labelledby'));
  assert.equal(find(strip, (n) => n.localName === 'h2').textContent, 'Qué se ha analizado');
  assert.match(value(strip, 'from'), /Banco Santander/);
  assert.match(value(strip, 'from'), /avisos@santander-seguridad\.test/);
  const domain = find(row(strip, 'from'), (n) => n.classList?.contains('analyzed__domain'));
  assert.equal(domain.textContent, 'santander-seguridad.test');
  assert.equal(value(strip, 'subject'), 'Último aviso: su cuenta ha sido bloqueada');
  assert.match(value(strip, 'date'), /2026/);
  assert.equal(value(strip, 'links'), '1');
  assert.equal(value(strip, 'attachments'), '0');
  assert.match(value(strip, 'auth'), /SPF falla · DKIM sin resultado · DMARC falla/);
  assert.match(value(strip, 'auth'), /Declarado por/);
});

test('muestra 06: adjunto con su nombre', () => {
  const strip = analyzedStrip(sample('06'), { kind: 'eml' });
  assert.match(value(strip, 'attachments'), /^1 · Factura_2026-1187\.pdf\.exe$/);
  assert.equal(value(strip, 'auth'), 'Sin datos de autenticación');
});

test('más de tres adjuntos: tres nombres y «y N más»', () => {
  const report = sample('06');
  report.email.attachments = ['a.pdf', 'b.pdf', 'c.pdf', 'd.pdf', 'e.pdf'].map((filename) => ({ filename }));
  assert.equal(value(analyzedStrip(report, { kind: 'eml' }), 'attachments'), '5 · a.pdf, b.pdf, c.pdf y 2 más');
});

test('enlaces: se cuentan direcciones distintas, no apariciones', () => {
  const report = sample('03');
  report.email.links = [{ href: 'https://a.test/' }, { href: 'https://a.test/' }, { href: 'https://b.test/' }];
  assert.equal(value(analyzedStrip(report, { kind: 'eml' }), 'links'), '2');
});

test('URL suelta: muestra la URL con el host resaltado y avisa de que no hay remitente ni cabeceras', () => {
  const report = analyzeInput({ kind: 'url', value: 'https://paypa1.com/login?x=1' });
  const strip = analyzedStrip(report, { kind: 'url' });
  assert.equal(value(strip, 'url'), 'https://paypa1.com/login?x=1');
  assert.equal(find(row(strip, 'url'), (n) => n.classList?.contains('analyzed__domain')).textContent, 'paypa1.com');
  assert.equal(row(strip, 'from'), null);
  assert.equal(row(strip, 'auth'), null);
  assert.match(find(strip, (n) => n.classList?.contains('analyzed__note')).textContent, /Solo se ha analizado la URL/);
});

test('texto pegado sin cabeceras: lo dice en lugar de enseñar campos vacíos', () => {
  const report = analyzeInput({ kind: 'text', value: 'Hola, pulsa aquí https://example.test/a para confirmar.' });
  const strip = analyzedStrip(report, { kind: 'text' });
  assert.equal(row(strip, 'from'), null);
  assert.equal(row(strip, 'auth'), null);
  assert.equal(value(strip, 'links'), '1');
  assert.match(find(strip, (n) => n.classList?.contains('analyzed__note')).textContent, /sin cabeceras/);
});

test('correo sin asunto, sin remitente ni fecha: dice que faltan', () => {
  const report = analyzeInput({ kind: 'eml', value: 'To: a@b.test\r\nX-Foo: 1\r\n\r\ncuerpo' });
  const strip = analyzedStrip(report, { kind: 'eml' });
  assert.equal(value(strip, 'from'), 'Sin remitente');
  assert.equal(value(strip, 'subject'), '(sin asunto)');
  assert.equal(value(strip, 'date'), 'Sin fecha');
});

test('fecha que no se entiende: se enseña tal cual, recortada', () => {
  const report = sample('03');
  report.email.date = 'el martes por la tarde';
  assert.equal(value(analyzedStrip(report, { kind: 'eml' }), 'date'), 'el martes por la tarde');
});

test('asunto enorme: se recorta y el texto completo queda en title', () => {
  const report = sample('03');
  report.email.subject = 'A'.repeat(1000);
  const dd = find(row(analyzedStrip(report, { kind: 'eml' }), 'subject'), (n) => n.localName === 'dd');
  assert.ok(dd.textContent.length <= 201, String(dd.textContent.length));
  assert.ok(dd.textContent.endsWith('…'));
});

test('un RLO del asunto se muestra visible (Trojan Source), nunca reordena el texto', () => {
  const report = sample('03');
  report.email.subject = 'Factura \u202Efdp.exe';
  assert.match(value(analyzedStrip(report, { kind: 'eml' }), 'subject'), /⟦U\+202E⟧/);
});

test('en inglés: mismos campos con sus etiquetas traducidas', () => {
  setLang('en');
  try {
    const strip = analyzedStrip(sample('03'), { kind: 'eml' });
    assert.equal(find(strip, (n) => n.localName === 'h2').textContent, 'What was analyzed');
    assert.deepEqual(findAll(strip, (n) => n.localName === 'dt').map((n) => n.textContent),
      ['From', 'Subject', 'Date (as stated in the email)', 'Links', 'Attachments', 'Authentication']);
    assert.match(value(strip, 'auth'), /SPF fails · DKIM no result · DMARC fails/);
  } finally {
    setLang('es');
  }
});

test('todas las muestras pintan la franja sin lanzar', () => {
  for (const s of SAMPLES) {
    const strip = analyzedStrip(sample(s.file.slice(0, 2)), { kind: 'eml' });
    assert.ok(row(strip, 'links'), s.file);
  }
});
