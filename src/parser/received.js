// Ruta del email reconstruida a partir de las cabeceras Received.
import { registrableDomain } from './url.js';

const MAX_HOPS = 30;

const org = (host) => (host ? registrableDomain(host.toLowerCase().replace(/\.$/, '')) : '');

function parseTime(date) {
  if (!date) return null;
  // Date.parse no entiende el comentario final "(CEST)".
  const time = Date.parse(date.replace(/\([^)]*\)/g, ' ').trim());
  return Number.isNaN(time) ? null : time;
}

/** Interpreta un único valor de cabecera Received. */
export function parseHop(raw) {
  // Se acota cada cabecera: un Received de megas con "(" sin cerrar no debe bloquear los regex.
  const value = String(raw).slice(0, 1000);
  const helo = /\bfrom\s+(\S+)/i.exec(value)?.[1] ?? '';
  const date = value.includes(';') ? value.slice(value.lastIndexOf(';') + 1).trim() : '';
  return {
    // `from` se mantiene por compatibilidad: es el HELO, que elige el remitente.
    from: helo,
    helo,
    by: /\bby\s+([^\s;]+)/i.exec(value)?.[1] ?? '',
    // Nombre inverso que escribió el servidor receptor: "from helo (rdns [IP])".
    rdns: /\bfrom\s+\S+\s+\(\s*([^\s()[\]]+)\s*\[/i.exec(value)?.[1]?.toLowerCase() ?? '',
    // La IP que vio el servidor receptor va entre paréntesis: "from x (host [IP])".
    ip: (/\([^)]*\[([0-9a-f.:]+)\][^)]*\)/i.exec(value) ?? /\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*)\]/i.exec(value))?.[1] ?? '',
    date,
    time: parseTime(date),
    raw: value,
  };
}

const receivedOf = (email) => (email.headerList ?? [])
  .filter((h) => h.name === 'received')
  .slice(0, MAX_HOPS)
  .map((h) => ({ index: h.index, ...parseHop(h.value) }));

/**
 * El salto en el que el receptor aceptó el correo desde fuera: el Received más bajo del bloque
 * superior de saltos de la organización receptora. Todo lo que hay debajo lo escribió otro.
 */
export function receivingHop(email) {
  const received = receivedOf(email);
  const receiver = received[0]?.by?.toLowerCase() || null;
  const receiverOrg = org(receiver);
  let entry = null;
  for (const hop of received) {
    if (!receiver || !hop.by || org(hop.by) !== receiverOrg) break;
    entry = hop;
    // El salto solo es interno si el receptor resolvió al emisor (rDNS) dentro de su organización.
    // Un HELO o un Received escrito por el remitente no puede alargar la zona de confianza.
    const sender = hop.rdns && hop.rdns !== 'unknown' ? hop.rdns : '';
    if (!sender || org(sender) !== receiverOrg) break;
  }
  const boundary = entry ? received.find((hop) => hop.index > entry.index) ?? null : null;
  return { receiver, receiverOrg, entry, boundary };
}

/**
 * Ruta en orden de llegada y el índice (en `hops`) del salto de entrada al receptor.
 * @returns {{ hops: Array, firstExternal: number|null, parsed: number }}
 */
export function parseRoute(email) {
  const received = receivedOf(email);
  const { entry } = receivingHop(email);
  const hops = [...received].reverse();
  const firstExternal = entry ? hops.findIndex((h) => h.index === entry.index) : null;
  return {
    hops: hops.map(({ index, ...hop }) => hop),
    firstExternal: firstExternal === -1 ? null : firstExternal,
    parsed: hops.filter((h) => h.by || h.helo).length,
  };
}

/** Ruta para el informe, en orden de llegada, sin el texto crudo. */
export function parseReceived(email) {
  const { hops, firstExternal } = parseRoute(email);
  return hops.map(({ raw, ...hop }, i) => (i === firstExternal ? { ...hop, entry: true } : hop));
}
