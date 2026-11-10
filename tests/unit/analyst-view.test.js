// Modo analista (spec 2.3, §2): navegación agrupada y un panel por vista.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { installDom, find, findAll, tag } from '../helpers/dom.js';
import { SAMPLES } from '../../samples/index.js';
import { analyzeInput } from '../../src/core/engine.js';

let dom;
let renderAnalyst;
let modeSwitch;
before(async () => {
  dom = installDom();
  globalThis.matchMedia = () => ({ matches: true });
  globalThis.requestAnimationFrame = () => 0;
  ({ renderAnalyst } = await import('../../src/ui/views/analyst.js'));
  ({ modeSwitch } = await import('../../src/ui/components/mode-switch.js'));
});
after(() => {
  dom.restore();
  delete globalThis.matchMedia;
  delete globalThis.requestAnimationFrame;
});

const report = (prefix) => {
  const s = SAMPLES.find((x) => x.file.startsWith(prefix));
  return analyzeInput({ kind: 'eml', value: readFileSync(new URL(`../../samples/${s.file}`, import.meta.url), 'utf8') });
};
const has = (cls) => (n) => n.classList.contains(cls);

test('muestra 03, vista señales: navegación con 9 enlaces (con «URLs» y «Panel») y 15 tarjetas', () => {
  const r = report('03');
  const view = renderAnalyst(r, 'senales');
  const nav = find(view, tag('nav'));
  assert.equal(nav.getAttribute('aria-label'), 'Secciones del informe');
  const links = findAll(nav, tag('a'));
  assert.equal(links.length, 9);
  const current = links.filter((a) => a.getAttribute('aria-current') === 'page');
  assert.equal(current.length, 1);
  assert.equal(current[0].getAttribute('href'), '#analista/senales');
  assert.deepEqual(findAll(nav, tag('h3')).map((h) => h.textContent), ['Correo', 'Inteligencia', 'Historial']);
  assert.match(current[0].textContent, new RegExp(String(r.findings.length)));
  const panel = find(view, has('view'));
  assert.equal(r.findings.length, 15);
  assert.equal(findAll(panel, has('finding')).length, 15);
  const h2 = find(panel, tag('h2'));
  assert.equal(h2.getAttribute('tabindex'), '-1');
  assert.equal(panel.getAttribute('aria-labelledby'), h2.id);
});

test('vista attack: tabla de técnicas', () => {
  const panel = find(renderAnalyst(report('03'), 'attack'), has('view'));
  assert.ok(find(panel, tag('table')));
  assert.ok(findAll(panel, tag('th')).some((n) => n.textContent === 'Técnica'));
});

test('vista resumen: anillo, nivel y confianza, sin botones de acción', () => {
  const panel = find(renderAnalyst(report('03'), 'resumen'), has('view'));
  assert.ok(find(panel, has('gauge')));
  assert.ok(find(panel, has('confidence')));
  assert.equal(find(panel, (n) => ['export-json', 'new'].includes(n.getAttribute('data-action'))), null);
});

test('URL suelta: sin autenticación ni cabeceras en la navegación', () => {
  const r = analyzeInput({ kind: 'url', value: 'http://192.0.2.1/login' });
  const hrefs = findAll(find(renderAnalyst(r, 'resumen'), tag('nav')), tag('a')).map((a) => a.getAttribute('href'));
  assert.ok(!hrefs.includes('#analista/autenticacion'));
  assert.ok(!hrefs.includes('#analista/cabeceras'));
  assert.ok(hrefs.includes('#analista/senales'));
});

test('modeSwitch: grupo con dos botones y aria-pressed', () => {
  const s = modeSwitch('analyst');
  assert.equal(s.getAttribute('role'), 'group');
  assert.equal(s.getAttribute('aria-label'), 'Nivel de detalle');
  const buttons = findAll(s, tag('button'));
  assert.deepEqual(buttons.map((b) => [b.textContent, b.getAttribute('data-action'), b.getAttribute('aria-pressed')]),
    [['Sencillo', 'mode-simple', 'false'], ['Modo analista', 'mode-analyst', 'true']]);
  assert.equal(findAll(modeSwitch('raro'), tag('button'))[0].getAttribute('aria-pressed'), 'true');
});

test('vista adjuntos (muestra 12): tabla con 5 columnas, una fila por adjunto, y hashes aparte', () => {
  const r = report('12-');
  const nav = find(renderAnalyst(r, 'senales'), tag('nav'));
  assert.ok(findAll(nav, tag('a')).some((a) => a.getAttribute('href') === '#analista/adjuntos'));
  const view = renderAnalyst(r, 'adjuntos');
  const table = find(view, tag('table'));
  assert.ok(table);
  assert.equal(find(table, tag('caption')).textContent, 'Adjuntos');
  assert.deepEqual(findAll(table, tag('th')).filter((n) => n.getAttribute('scope') === 'col').map((n) => n.textContent),
    ['Nombre', 'Tipo declarado', 'Tipo real', 'Tamaño', 'Dentro']);
  assert.equal(findAll(find(table, tag('tbody')), tag('tr')).length, r.email.attachments.length);
  const hashes = find(view, (n) => n.classList.contains('hash-card'));
  assert.match(hashes.textContent, /SHA-256/);
  assert.match(hashes.textContent, /MD5/);
  assert.ok(hashes.textContent.includes(r.email.attachments[0].sha1));
  assert.match(table.textContent, /JavaScript/);
  assert.match(table.textContent, /cifrad/);
});

test('vista adjuntos (muestra 11): el tipo real que no cuadra va en un chip de phishing', () => {
  const table = find(renderAnalyst(report('11-'), 'adjuntos'), tag('table'));
  const bad = find(table, (n) => n.classList.contains('chip--phishing'));
  assert.equal(bad.textContent, 'Ejecutable de Windows');
  // El color no es la única señal (WCAG 1.4.1): también se dice en texto.
  assert.match(bad.parentNode.textContent, /No coincide con \.pdf/);
  const ok = find(find(renderAnalyst(report('12-'), 'adjuntos'), tag('table')), tag('tbody'));
  assert.doesNotMatch(ok.textContent, /No coincide/);
});

test('vista cabeceras ya no repite los adjuntos', () => {
  const view = renderAnalyst(report('06-'), 'cabeceras');
  assert.doesNotMatch(view.textContent, /Adjuntos \(1\)/);
});

test('crítica de diseño: «Historial» no dice 0 cuando no lo sabe; en el Panel usa el total guardado', () => {
  const r = report('03');
  const countOf = (view) => {
    const link = findAll(find(view, tag('nav')), tag('a')).find((a) => a.getAttribute('href') === '#analista/historial');
    return find(link, has('nav-rail__count'))?.textContent ?? null;
  };
  assert.equal(countOf(renderAnalyst(r, 'senales', { historyEnabled: true })), null, 'sin datos del historial no hay número');
  const stats = { totals: { analyses: 7, phishingOrWorse: 0, campaigns: 0, distinctIocs: 0, dangerousPct: 0 }, timeline: { unit: 'day', buckets: [], omitted: 0 }, techniques: [], iocs: [], senders: [], domains: [], campaigns: [] };
  assert.equal(countOf(renderAnalyst(r, 'panel', { historyEnabled: true, dashboard: { stats } })), '7');
});
