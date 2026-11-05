// SPF (RFC 7208) sin DNS: solo se evalúa si el analista pega el registro TXT, y solo los
// mecanismos que no necesitan consultas (ip4, ip6, all). Si antes de un acierto aparece uno
// que sí las necesita (include, a, mx…), el resultado honesto es "no verificable".
import { receivingHop } from './trust.js';
import { parseIp } from '../lib/ip.js';

const QUALIFIERS = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };
const NEEDS_DNS = /^(include|a|mx|ptr|exists)(?=$|[:/])/;
const MAX_TERMS = 50;

/** IP del servidor que entregó el correo al receptor, o null. */
export function originIp(email) {
  return receivingHop(email).entry?.ip || null;
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
