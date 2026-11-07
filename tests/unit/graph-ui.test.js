// Vista «IOCs» (spec 2.3, §5.2): grafo SVG con createElementNS, teclado y tabla equivalente.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll } from '../helpers/dom.js';
import { BATCHES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeBatch } from '../../src/core/batch.js';
import { buildGraph, NODE_LABELS } from '../../src/intel/graph.js';
import { layoutGraph } from '../../src/intel/layout.js';

const SVG = 'http://www.w3.org/2000/svg';
let dom;
let M;
let graph;
before(async () => {
  dom = installDom();
  M = {
    ...(await import('../../src/ui/dom.js')),
    ...(await import('../../src/ui/components/graph.js')),
    ...(await import('../../src/ui/panels/iocs.js')),
  };
  const files = BATCHES[0].files.map((f) => ({ name: f.split('/').pop(), size: 1, text: async () => SAMPLE_TEXTS[f] }));
  graph = buildGraph((await analyzeBatch(files, { yieldFn: async () => {} })).entries);
});
after(() => dom.restore());

const nodesOf = (root) => findAll(root, (n) => n.localName === 'g' && n.getAttribute('data-node'));

test('svgEl: namespace SVG, lista blanca de atributos y texto como texto', () => {
  const t = M.svgEl('text', { attrs: { x: '1', y: '2' }, text: '<img src=x onerror=alert(1)>' });
  assert.equal(t.namespaceURI, SVG);
  assert.equal(t.textContent, '<img src=x onerror=alert(1)>');
  assert.equal(t.childNodes[0].nodeType, 3);
  assert.throws(() => M.svgEl('g', { attrs: { onload: 'x' } }), /no permitid[oa]/);
  assert.throws(() => M.svgEl('a', { attrs: { href: 'javascript:x' } }), /no permitid[oa]/);
  assert.throws(() => M.svgEl('foreignObject'), /no permitid[oa]/);
});

test('graphView del lote: un nodo por nodo dispuesto, un solo paso de Tab y etiquetas defanged', () => {
  const layout = layoutGraph(graph);
  const view = M.graphView(M.graphModel(graph, layout));
  const svg = find(view, (n) => n.localName === 'svg');
  assert.equal(svg.namespaceURI, SVG);
  assert.equal(svg.getAttribute('role'), 'group');
  assert.match(svg.getAttribute('aria-label'), /^Grafo de IOCs: \d+ nodos y \d+ relaciones$/);
  const nodes = nodesOf(view);
  assert.equal(nodes.length, layout.nodes.length);
  assert.equal(nodes.filter((n) => n.getAttribute('tabindex') === '0').length, 1);
  assert.ok(nodes.every((n) => n.getAttribute('role') === 'img'));
  const labels = Object.values(NODE_LABELS);
  for (const n of nodes) assert.ok(labels.some((l) => n.getAttribute('aria-label').startsWith(`${l} `)), n.getAttribute('aria-label'));
  const domain = nodes.find((n) => n.getAttribute('aria-label').startsWith('Dominio correos-envios'));
  assert.match(domain.getAttribute('aria-label'), /^Dominio correos-envios\[\.\]test, \d+ relaciones?$/);
  assert.ok(!view.textContent.includes('correos-envios.test'), 'ningún dominio sin defang');
  const legend = find(view, (n) => n.className === 'graph__legend');
  for (const l of labels) assert.ok(legend.textContent.includes(l), l);
});

test('graphView avisa cuando no caben todos los nodos', () => {
  const links = Array.from({ length: 200 }, (_, i) => ({ href: `https://h${i}.test/` }));
  const big = buildGraph([{ key: 'k', name: 'k.eml', report: { level: 'phishing', email: { links } } }]);
  const view = M.graphView(M.graphModel(big, layoutGraph(big)));
  assert.ok(view.textContent.includes(`Se dibujan los 150 nodos más conectados de ${big.nodes.length}.`));
  assert.ok(!view.textContent.includes('la tabla tiene el resto'));
});

test('graphKey: flechas con vuelta, Inicio y Fin', () => {
  assert.equal(M.graphKey(0, 'ArrowRight', 3), 1);
  assert.equal(M.graphKey(0, 'ArrowDown', 3), 1);
  assert.equal(M.graphKey(2, 'ArrowRight', 3), 0);
  assert.equal(M.graphKey(0, 'ArrowLeft', 3), 2);
  assert.equal(M.graphKey(1, 'ArrowUp', 3), 0);
  assert.equal(M.graphKey(1, 'Home', 3), 0);
  assert.equal(M.graphKey(0, 'End', 3), 2);
  assert.equal(M.graphKey(0, 'a', 3), null);
});

test('graphTable: como mucho 500 filas, primero lo compartido por más correos, y con los correos por nombre', () => {
  const nodes = [
    ...Array.from({ length: 600 }, (_, i) => ({ id: `domain:d${i}.test`, type: 'domain', value: `d${i}.test`, label: `d${i}.test`, emails: ['k1'] })),
    { id: `hash:${'a'.repeat(64)}`, type: 'hash', value: 'a'.repeat(64), label: 'factura.pdf', emails: ['k1', 'k2', 'k3', 'k4', 'k5'] },
  ];
  const names = new Map([['k1', 'uno.eml'], ['k2', 'dos.eml'], ['k3', 'tres.eml'], ['k4', 'cuatro.eml'], ['k5', 'cinco.eml']]);
  const table = M.graphTable({ nodes, edges: [] }, names);
  const rows = findAll(table, (n) => n.localName === 'tr');
  assert.equal(rows.length, 501);
  assert.equal(rows[1].children[1].textContent, 'factura.pdf');
  assert.equal(rows[1].children[2].textContent, 'cinco.eml, cuatro.eml, dos.eml y 2 más');
  assert.equal(rows[2].children[2].textContent, 'uno.eml');
  assert.ok(table.textContent.includes('Se muestran 500 de 601, primero los compartidos por más correos.'));
});
