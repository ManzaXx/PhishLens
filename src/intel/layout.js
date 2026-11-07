// Disposición radial determinista del grafo (sin simulación física): los correos en un anillo
// interior y los IOCs en uno exterior, cada uno cerca del ángulo medio de sus correos.
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const round = (v) => Math.round(v * 10) / 10;
const TAU = Math.PI * 2;

/**
 * @returns {{nodes: Array<{id, x, y}>, edges: Array<{from, to, type}>, hidden: number}}
 */
export function layoutGraph(graph, { maxNodes = 150, size = 640 } = {}) {
  const degree = new Map(graph.nodes.map((n) => [n.id, 0]));
  for (const e of graph.edges) {
    degree.set(e.from, (degree.get(e.from) ?? 0) + 1);
    degree.set(e.to, (degree.get(e.to) ?? 0) + 1);
  }
  const emails = graph.nodes.filter((n) => n.type === 'email').slice(0, maxNodes);
  const others = graph.nodes
    .filter((n) => n.type !== 'email')
    .sort((a, b) => degree.get(b.id) - degree.get(a.id) || cmp(a.id, b.id))
    .slice(0, Math.max(0, maxNodes - emails.length));
  const c = size / 2;
  const angleOf = new Map();
  const placed = [];
  emails.forEach((n, i) => {
    const angle = (TAU * i) / emails.length - Math.PI / 2;
    angleOf.set(n.value, angle);
    const r = emails.length === 1 ? 0 : size * 0.22;
    placed.push({ id: n.id, x: round(c + r * Math.cos(angle)), y: round(c + r * Math.sin(angle)) });
  });
  const mean = (n) => {
    let sx = 0;
    let sy = 0;
    for (const k of n.emails) {
      const a = angleOf.get(k);
      if (a === undefined) continue;
      sx += Math.cos(a);
      sy += Math.sin(a);
    }
    const a = sx === 0 && sy === 0 ? -Math.PI / 2 : Math.atan2(sy, sx);
    return round((a + TAU) % TAU);
  };
  const ring = others.map((n) => ({ n, a: mean(n) })).sort((x, y) => x.a - y.a || cmp(x.n.id, y.n.id));
  const start = ring.length ? ring[0].a : 0;
  ring.forEach(({ n }, i) => {
    const angle = start + (TAU * i) / ring.length;
    const r = size * 0.42;
    placed.push({ id: n.id, x: round(c + r * Math.cos(angle)), y: round(c + r * Math.sin(angle)) });
  });
  const ids = new Set(placed.map((p) => p.id));
  return {
    nodes: placed,
    edges: graph.edges.filter((e) => ids.has(e.from) && ids.has(e.to)),
    hidden: graph.nodes.length - placed.length,
  };
}
