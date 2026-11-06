// Componentes de presentación (spec 2.3, §4): estructura accesible y texto siempre como texto.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll, tag } from '../helpers/dom.js';

let dom;
let C;
before(async () => {
  dom = installDom();
  C = {
    ...(await import('../../src/ui/dom.js')),
    ...(await import('../../src/ui/components/severity-tag.js')),
    ...(await import('../../src/ui/components/chip.js')),
    ...(await import('../../src/ui/components/meter.js')),
    ...(await import('../../src/ui/components/empty-state.js')),
    ...(await import('../../src/ui/components/data-table.js')),
    ...(await import('../../src/ui/components/finding-card.js')),
    ...(await import('../../src/ui/components/signal-row.js')),
    ...(await import('../../src/ui/components/verdict-card.js')),
    ...(await import('../../src/ui/components/step-list.js')),
  };
});
after(() => dom.restore());

const FINDING = {
  id: 'sender.brand', detector: 'sender', severity: 'high', reliability: 'high', points: 12, polarity: 'risk',
  title: 'Suplanta a Santander', detail: 'El nombre dice Santander y el dominio no.', evidence: 'avisos@santander-seguridad.test',
  plain: 'Se hace pasar por Santander',
  techniques: [{ id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', why: 'enlace', url: 'https://attack.mitre.org/techniques/T1566/002/' }],
};

test('severityTag: texto y clase por gravedad; una clave rara cae en INFO', () => {
  const high = C.severityTag('high');
  assert.equal(high.textContent, 'GRAVE');
  assert.ok(high.classList.contains('sev--high'));
  assert.equal(C.severityTag('medium').textContent, 'MEDIA');
  assert.equal(C.severityTag('low').textContent, 'LEVE');
  for (const odd of ['constructor', '__proto__', 'toString', undefined]) {
    const t = C.severityTag(odd);
    assert.equal(t.textContent, 'INFO', String(odd));
    assert.ok(t.classList.contains('sev--info'), String(odd));
  }
});

test('meter: cifra con aria-label «x de y» y barra con --w', () => {
  const m = C.meter({ label: 'Remitente', value: 18, max: 20, severity: 'high' });
  assert.ok(find(m, (n) => n.getAttribute('aria-label') === '18 de 20'));
  const bar = find(m, (n) => n.style.getPropertyValue('--w'));
  assert.equal(bar.style.getPropertyValue('--w'), '90%');
  assert.match(m.textContent, /Remitente/);
  // Valores fuera de rango no rompen la barra.
  const over = C.meter({ label: 'x', value: 30, max: 20 });
  assert.equal(find(over, (n) => n.style.getPropertyValue('--w')).style.getPropertyValue('--w'), '100%');
  const zero = C.meter({ label: 'x', value: 1, max: 0 });
  assert.equal(find(zero, (n) => n.style.getPropertyValue('--w')).style.getPropertyValue('--w'), '0%');
  assert.ok(find(C.meter({ label: 'x', value: 2.5, max: 10 }), (n) => n.getAttribute('aria-label') === '2,5 de 10'));
});

test('dataTable: caption, th[scope=col] por columna y contenedor desplazable con foco', () => {
  const t = C.dataTable({ caption: 'Señales', columns: ['Gravedad', 'Señal', 'Evidencia'], rows: [['GRAVE', 'a', 'b'], ['MEDIA', 'c', 'd']] });
  assert.ok(t.classList.contains('table-scroll'));
  assert.equal(t.getAttribute('tabindex'), '0');
  assert.equal(t.getAttribute('role'), 'region');
  assert.equal(t.getAttribute('aria-label'), 'Señales');
  assert.equal(find(t, tag('caption')).textContent, 'Señales');
  const ths = findAll(t, tag('th')).filter((n) => n.getAttribute('scope') === 'col');
  assert.deepEqual(ths.map((n) => n.textContent), ['Gravedad', 'Señal', 'Evidencia']);
  assert.equal(findAll(t, tag('tr')).length, 3);
  // Una celda puede ser un nodo ya hecho.
  const withNode = C.dataTable({ caption: 'x', columns: ['a'], rows: [[C.severityTag('high')]] });
  assert.ok(find(withNode, (n) => n.classList.contains('sev--high')));
});

test('verdictCard: h2 con el titular, aria-labelledby a su id y tono en la clase', () => {
  const v = { tone: 'phishing', headline: 'No te fíes: es phishing', because: 'Dice ser de tu banco, pero no lo es.', steps: [], top: [] };
  const card = C.verdictCard(v, { score: 95, confidence: { level: 'high' } });
  assert.equal(card.localName, 'section');
  assert.ok(card.classList.contains('verdict--phishing'));
  const h2 = find(card, tag('h2'));
  assert.equal(h2.textContent, v.headline);
  assert.ok(h2.id);
  assert.equal(card.getAttribute('aria-labelledby'), h2.id);
  assert.match(card.textContent, /95 de 100 · confianza alta/);
  assert.match(card.textContent, /Dice ser de tu banco/);
  // Dos tarjetas en la misma página no comparten id.
  assert.notEqual(find(C.verdictCard(v, { score: 1 }), tag('h2')).id, h2.id);
  // Sin confianza no se inventa una.
  assert.doesNotMatch(C.verdictCard(v, { score: 95 }).textContent, /confianza/);
});

test('stepList: ol con un li por paso', () => {
  const list = C.stepList(['a', 'b', 'c']);
  assert.equal(list.localName, 'ol');
  assert.deepEqual(list.children.map((n) => [n.localName, n.textContent]), [['li', 'a'], ['li', 'b'], ['li', 'c']]);
});

test('findingCard: gravedad, fiabilidad y técnica ATT&CK con enlace solo a MITRE', () => {
  const card = C.findingCard(FINDING);
  assert.ok(find(card, (n) => n.classList.contains('sev--high')));
  assert.match(card.textContent, /fiabilidad alta · T1566\.002/);
  const link = find(card, tag('a'));
  assert.equal(link.getAttribute('href'), FINDING.techniques[0].url);
  assert.equal(link.getAttribute('rel'), 'noopener noreferrer');
  const evil = C.findingCard({ ...FINDING, techniques: [{ ...FINDING.techniques[0], url: 'javascript:alert(1)' }] });
  assert.equal(find(evil, tag('a')), null);
  // Una señal a favor no lleva técnica de ataque.
  assert.doesNotMatch(C.findingCard({ ...FINDING, polarity: 'trust' }).textContent, /T1566/);
});

test('signalRow: texto sencillo y gravedad en texto; sin plain usa el título', () => {
  const row = C.signalRow(FINDING);
  assert.match(row.textContent, /Se hace pasar por Santander/);
  assert.match(row.textContent, /Grave/);
  assert.match(C.signalRow({ ...FINDING, plain: undefined }).textContent, /Suplanta a Santander/);
});

test('chip y emptyState pintan su texto', () => {
  const chip = C.chip('3 correos', { tone: 'suspicious' });
  assert.equal(chip.textContent, '3 correos');
  assert.ok(chip.classList.contains('chip--suspicious'));
  const empty = C.emptyState('Nada por aquí', 'Pega un correo para empezar.');
  assert.match(empty.textContent, /Nada por aquí/);
  assert.match(empty.textContent, /Pega un correo/);
});

test('el HTML de un correo nunca se convierte en elementos', () => {
  const evil = '<img src=x onerror=1>';
  const nodes = [
    C.chip(evil), C.emptyState(evil, evil), C.stepList([evil]),
    C.meter({ label: evil, value: 1, max: 2 }),
    C.dataTable({ caption: evil, columns: [evil], rows: [[evil]] }),
    C.findingCard({ ...FINDING, title: evil, detail: evil, evidence: evil, plain: evil }),
    C.signalRow({ ...FINDING, plain: evil }),
    C.verdictCard({ tone: 'phishing', headline: evil, because: evil, steps: [], top: [] }, { score: 9 }),
  ];
  for (const node of nodes) {
    assert.equal(find(node, tag('img')), null);
    assert.match(node.textContent, /<img src=x onerror=1>/);
  }
});

test('el() muestra los caracteres de control bidireccionales en vez de aplicarlos', () => {
  assert.equal(C.el('span', { text: 'factura‮fdp.exe' }).textContent.includes('‮'), false);
});

test('icon(): SVG decorativo, y un nombre desconocido no rompe', () => {
  for (const name of ['alert', 'check', 'info', 'shield', 'menu', 'chevron']) {
    const i = C.icon(name);
    assert.equal(i.localName, 'svg');
    assert.equal(i.getAttribute('aria-hidden'), 'true');
    assert.ok(i.childElementCount > 0, name);
  }
  assert.equal(C.icon('constructor').localName, 'svg');
});
