import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph, NODE_TYPES, EDGE_TYPES, NODE_LABELS } from '../../src/intel/graph.js';
import { layoutGraph } from '../../src/intel/layout.js';
import { entry, shuffle } from '../helpers/batch.js';

const full = () => entry({
  key: 'aaa',
  email: {
    from: { address: 'a@Evil.test', name: 'A' },
    replyTo: { address: 'b@otro.test' },
    subject: 'Aviso',
    links: [{ href: 'https://login.evil.test/x' }],
    attachments: [{ filename: 'f.pdf', sha256: 'f'.repeat(64) }],
    route: [{ ip: '198.51.100.1' }, { ip: '203.0.113.5', entry: true }],
  },
});
const edgeSet = (g) => g.edges.map((e) => `${e.from} -${e.type}-> ${e.to}`);

test('tipos de nodo y arista fijos', () => {
  assert.deepEqual(NODE_TYPES, ['email', 'address', 'domain', 'ip', 'url', 'hash']);
  assert.deepEqual(EDGE_TYPES, ['envía', 'enlaza', 'adjunta', 'resuelve-en', 'responde-a']);
  assert.deepEqual(Object.keys(NODE_LABELS), NODE_TYPES);
  assert.equal(NODE_LABELS.domain, 'Dominio');
});

test('un correo completo da exactamente las aristas previstas', () => {
  const g = buildGraph([full()]);
  assert.deepEqual(edgeSet(g).sort(), [
    'address:a@evil.test -envía-> email:aaa',
    'domain:evil.test -envía-> email:aaa',
    'domain:evil.test -resuelve-en-> ip:203.0.113.5',
    'email:aaa -adjunta-> hash:' + 'f'.repeat(64),
    'email:aaa -enlaza-> url:https://login.evil.test/x',
    'email:aaa -responde-a-> address:b@otro.test',
    'url:https://login.evil.test/x -enlaza-> domain:login.evil.test',
  ].sort());
  const email = g.nodes.find((x) => x.id === 'email:aaa');
  assert.equal(email.label, 'Aviso');
  assert.equal(g.nodes.find((x) => x.type === 'hash').label, 'f.pdf');
  assert.deepEqual(g.nodes.map((x) => x.type), [...g.nodes.map((x) => x.type)].sort((a, b) => NODE_TYPES.indexOf(a) - NODE_TYPES.indexOf(b)));
});

test('IP de entrada privada: sin resuelve-en; enlace a una IP: nodo ip', () => {
  const g = buildGraph([entry({ key: 'b', email: { from: { address: 'x@y.test' }, route: [{ ip: '10.0.0.1', entry: true }], links: [{ href: 'http://192.0.2.9/a' }] } })]);
  assert.ok(!g.edges.some((e) => e.type === 'resuelve-en'));
  assert.ok(edgeSet(g).includes('url:http://192.0.2.9/a -enlaza-> ip:192.0.2.9'));
});

test('sin asunto el correo se llama como el fichero; Reply-To igual al From no crea responde-a', () => {
  const g = buildGraph([entry({ key: 'c', name: 'c.eml', email: { from: { address: 'x@y.test' }, replyTo: { address: 'X@y.test' } } })]);
  assert.equal(g.nodes.find((x) => x.type === 'email').label, 'c.eml');
  assert.ok(!g.edges.some((e) => e.type === 'responde-a'));
});

test('dos correos del mismo dominio comparten nodo', () => {
  const g = buildGraph([
    entry({ key: 'e1', email: { from: { address: 'a@evil.test' } } }),
    entry({ key: 'e2', email: { from: { address: 'b@evil.test' } } }),
  ]);
  const d = g.nodes.filter((x) => x.id === 'domain:evil.test');
  assert.equal(d.length, 1);
  assert.deepEqual(d[0].emails, ['e1', 'e2']);
});

const six = () => Array.from({ length: 6 }, (_, i) => entry({
  key: `s${i}`,
  email: {
    from: { address: `u${i}@d${i % 2}.test` },
    links: [{ href: `https://l${i % 3}.test/p` }],
    attachments: i % 2 ? [{ filename: 'a', sha256: String(i % 4).repeat(64) }] : [],
    route: [{ ip: `203.0.113.${i % 2}`, entry: true }],
  },
}));

test('propiedad: el orden de los correos no cambia ni el grafo ni la disposición', () => {
  const base = six();
  const g = buildGraph(base);
  const l = layoutGraph(g);
  for (let seed = 1; seed <= 20; seed++) {
    const g2 = buildGraph(shuffle(base, seed));
    assert.deepEqual(g2, g);
    assert.deepEqual(layoutGraph(g2), l);
  }
});

test('disposición: un correo va al centro; con 400 IOCs se dibujan 150 y los correos siempre se quedan', () => {
  const one = layoutGraph(buildGraph([full()]), { size: 640 });
  assert.deepEqual(one.nodes.find((x) => x.id === 'email:aaa'), { id: 'email:aaa', x: 320, y: 320 });
  const links = Array.from({ length: 200 }, (_, i) => ({ href: `https://h${i}.test/` }));
  const big = layoutGraph(buildGraph([entry({ key: 'big', email: { links } })]));
  assert.equal(big.nodes.length, 150);
  assert.equal(big.hidden, 251);
  assert.ok(big.nodes.some((x) => x.id === 'email:big'));
  const ids = new Set(big.nodes.map((x) => x.id));
  assert.ok(big.edges.every((e) => ids.has(e.from) && ids.has(e.to)));
  for (const p of [...big.nodes, ...one.nodes]) assert.ok(p.x >= 0 && p.x <= 640 && p.y >= 0 && p.y <= 640);
});
