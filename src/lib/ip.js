// Direcciones IP como enteros (BigInt) para comparar rangos CIDR sin dependencias.

function ipv4(text) {
  const parts = String(text).split('.');
  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
  return parts.reduce((n, p) => (n << 8n) | BigInt(p), 0n);
}

function ipv6(text) {
  const value = String(text).toLowerCase();
  if (!/^[0-9a-f:]+$/.test(value) || (value.match(/::/g) ?? []).length > 1) return null;
  const [left, right = null] = value.split('::');
  const l = left ? left.split(':') : [];
  const r = right ? right.split(':') : [];
  const missing = 8 - l.length - r.length;
  if ((right === null && missing !== 0) || missing < 0) return null;
  const groups = [...l, ...Array(right === null ? 0 : missing).fill('0'), ...r];
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n);
}

/** { family: 4|6, value: bigint, bits } o null. */
export function parseIp(text) {
  const v4 = ipv4(text);
  if (v4 !== null) return { family: 4, value: v4, bits: 32 };
  const v6 = ipv6(text);
  return v6 !== null ? { family: 6, value: v6, bits: 128 } : null;
}

/** ¿Está `ip` (ya parseada) dentro de `network/prefix`? */
export function inCidr(ip, network, prefix) {
  if (!ip || !network || ip.family !== network.family) return false;
  const shift = BigInt(network.bits - prefix);
  return (ip.value >> shift) === (network.value >> shift);
}

// Rangos que nunca deberían ser el origen público de un correo.
const RESERVED = [
  ['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['100.64.0.0', 10],
  ['127.0.0.0', 8], ['169.254.0.0', 16], ['0.0.0.0', 8],
  ['::1', 128], ['::', 128], ['fc00::', 7], ['fe80::', 10],
].map(([net, prefix]) => [parseIp(net), prefix]);

/** IP privada, de loopback, link-local o CGNAT. */
export function isReservedIp(text) {
  const ip = parseIp(text);
  return Boolean(ip) && RESERVED.some(([net, prefix]) => inCidr(ip, net, prefix));
}
