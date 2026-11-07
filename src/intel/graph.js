// Grafo de IOCs de un lote (spec 2.3, §5.2). Determinista: el mismo lote en cualquier orden da el
// mismo grafo. No hay red: `resuelve-en` solo une el dominio del remitente con la IP del salto de
// entrada que figura en las propias cabeceras.
import { parseUrl, unwrapUrl } from '../parser/url.js';
import { isReservedIp } from '../lib/ip.js';

export const NODE_TYPES = Object.freeze(['email', 'address', 'domain', 'ip', 'url', 'hash']);
export const EDGE_TYPES = Object.freeze(['envía', 'enlaza', 'adjunta', 'resuelve-en', 'responde-a']);
export const NODE_LABELS = Object.freeze({ email: 'Correo', address: 'Dirección', domain: 'Dominio', ip: 'IP', url: 'URL', hash: 'Hash' });

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

const lowerAddress = (a) => (a?.address && a.address.includes('@') ? a.address.toLowerCase() : null);

/** IP pública del salto de entrada del correo, o null. */
export function entryIp(report) {
  const hop = (report?.email?.route ?? []).find((h) => h.entry);
  return hop?.ip && !isReservedIp(hop.ip) ? hop.ip : null;
}

/** Dominio del remitente (From), en minúsculas, o null. */
export const senderDomain = (report) => lowerAddress(report?.email?.from)?.split('@')[1] || null;

/** Enlaces del correo ya desenvueltos y parseados (sin los que no son http/https). */
export function linkUrls(report) {
  const out = [];
  for (const link of report?.email?.links ?? []) {
    const url = parseUrl(unwrapUrl(link.href) ?? link.href);
    if (url) out.push(url);
  }
  return out;
}

/**
 * @param {Array<{key, name, report}>} entries
 * @returns {{nodes: Array<{id, type, value, label, emails: string[]}>, edges: Array<{from, to, type}>}}
 */
export function buildGraph(entries) {
  const nodes = new Map();
  const edges = new Map();
  const node = (type, value, label, emailKey) => {
    const id = `${type}:${value}`;
    let n = nodes.get(id);
    if (!n) {
      n = { id, type, value, label: label ?? value, emails: new Set() };
      nodes.set(id, n);
    } else if (label && type === 'hash' && cmp(label, n.label) < 0) {
      n.label = label; // a igualdad de hash, el nombre menor: no depende del orden
    }
    n.emails.add(emailKey);
    return id;
  };
  const edge = (from, type, to) => edges.set(`${from}\u0000${to}\u0000${type}`, { from, to, type });

  for (const { key, name, report } of entries) {
    const email = report?.email ?? {};
    const me = node('email', key, email.subject || name || key, key);
    const from = lowerAddress(email.from);
    const domain = senderDomain(report);
    if (from) edge(node('address', from, null, key), 'envía', me);
    if (domain) {
      const d = node('domain', domain, null, key);
      edge(d, 'envía', me);
      const ip = entryIp(report);
      if (ip) edge(d, 'resuelve-en', node('ip', ip, null, key));
    }
    const reply = lowerAddress(email.replyTo);
    if (reply && reply !== from) edge(me, 'responde-a', node('address', reply, null, key));
    for (const url of linkUrls(report)) {
      const u = node('url', url.href, null, key);
      edge(me, 'enlaza', u);
      edge(u, 'enlaza', node(url.isIp ? 'ip' : 'domain', url.hostname, null, key));
    }
    for (const a of email.attachments ?? []) {
      if (a.sha256) edge(me, 'adjunta', node('hash', a.sha256, a.filename || a.sha256, key));
    }
  }
  return {
    nodes: [...nodes.values()]
      .map((n) => ({ ...n, emails: [...n.emails].sort(cmp) }))
      .sort((a, b) => NODE_TYPES.indexOf(a.type) - NODE_TYPES.indexOf(b.type) || cmp(a.id, b.id)),
    edges: [...edges.values()].sort((a, b) => cmp(a.from, b.from) || cmp(a.to, b.to) || cmp(a.type, b.type)),
  };
}
