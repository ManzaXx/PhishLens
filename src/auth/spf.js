// SPF (RFC 7208) sin DNS: solo se evalúa si el analista pega el registro TXT, y solo los
// mecanismos que no necesitan consultas (ip4, ip6, all). Si antes de un acierto aparece uno
// que sí las necesita (include, a, mx…), el resultado honesto es "no verificable".
import { receivingHop } from './trust.js';

const QUALIFIERS = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };
const NEEDS_DNS = /^(include|a|mx|ptr|exists)(?=$|[:/])/;
const MAX_TERMS = 50;

/** IP del servidor que entregó el correo al receptor, o null. */
export function originIp(email) {
  return receivingHop(email).entry?.ip || null;
}

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

function parseIp(text) {
  const v4 = ipv4(text);
  if (v4 !== null) return { family: 4, value: v4, bits: 32 };
  const v6 = ipv6(text);
  return v6 !== null ? { family: 6, value: v6, bits: 128 } : null;
}

/** ¿Está la IP dentro del rango "red/prefijo"? null si el rango no es válido. */
function inRange(ip, range, family) {
  const [net, prefixText] = range.split('/');
  const network = parseIp(net);
  if (!network || network.family !== family) return null;
  if (prefixText !== undefined && !/^\d{1,3}$/.test(prefixText)) return null;
  const prefix = prefixText === undefined ? network.bits : Number(prefixText);
  if (prefix > network.bits) return null;
  if (ip.family !== family) return false;
  const shift = BigInt(network.bits - prefix);
  return (ip.value >> shift) === (network.value >> shift);
}

/**
 * Evalúa un registro SPF para una IP.
 * @returns {{ result: 'pass'|'fail'|'softfail'|'neutral'|'unverifiable'|'permerror', mechanism: string|null, needs: string[] }}
 */
export function evaluateSpfRecord(record, ipText) {
  const terms = String(record ?? '').trim().slice(0, 2048).split(/\s+/);
  const ip = parseIp(ipText);
  const out = (result, mechanism = null, needs = []) => ({ result, mechanism, needs });
  if (terms[0]?.toLowerCase() !== 'v=spf1' || !ip) return out('permerror');
  const needs = [];
  for (const term of terms.slice(1, MAX_TERMS)) {
    const lower = term.toLowerCase();
    if (lower.startsWith('redirect=') || lower.startsWith('exp=')) {
      if (lower.startsWith('redirect=')) needs.push(term);
      continue;
    }
    // RFC 7208 §6: los modificadores desconocidos (nombre=valor) se ignoran.
    if (/^[a-z][a-z0-9_.-]*=/.test(lower)) continue;
    const qualifier = QUALIFIERS[term[0]] ? term[0] : '+';
    const mechanism = (QUALIFIERS[term[0]] ? term.slice(1) : term).toLowerCase();
    let match = false;
    if (mechanism === 'all') match = true;
    else if (mechanism.startsWith('ip4:') || mechanism.startsWith('ip6:')) {
      match = inRange(ip, mechanism.slice(4), mechanism.startsWith('ip4:') ? 4 : 6);
      if (match === null) return out('permerror');
    } else if (NEEDS_DNS.test(mechanism)) {
      needs.push(term);
      continue;
    } else {
      return out('permerror');
    }
    if (match) return needs.length ? out('unverifiable', null, needs) : out(QUALIFIERS[qualifier], term, []);
  }
  return needs.length ? out('unverifiable', null, needs) : out('neutral');
}
