// Detector de anomalías en la ruta Received (spec 2.2, §5).
import { finding } from '../core/finding.js';
import { parseRoute } from '../parser/received.js';
import { registrableDomain } from '../parser/url.js';
import { isReservedIp } from '../lib/ip.js';
import { BRANDS } from '../data/brands.js';
import { isOfficialDomain } from './sender.js';

export const name = 'route';

const SKEW_MS = 5 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_NORMAL_HOPS = 25;

/**
 * Avisos en texto para cada salto de la ruta del informe (en orden de llegada), con los
 * mismos criterios que el detector. La interfaz nunca depende solo del color.
 */
export function hopWarnings(route) {
  let previous = null;
  return route.map((hop) => {
    const out = [];
    if (hop.entry) out.push('Entrada al servidor receptor');
    if (hop.entry && hop.ip && isReservedIp(hop.ip)) out.push('IP privada en la frontera');
    if (hop.time !== null && hop.time !== undefined) {
      if (previous !== null && hop.time < previous - SKEW_MS) out.push('Hora anterior al salto previo');
      previous = hop.time;
    }
    return out;
  });
}

/** Lo mismo que hopWarnings, en códigos que la interfaz traduce (route.warn.*). */
export function hopWarningCodes(route) {
  const code = { 'Entrada al servidor receptor': 'route.warn.entry', 'IP privada en la frontera': 'route.warn.private-ip', 'Hora anterior al salto previo': 'route.warn.backwards' };
  return hopWarnings(route).map((list) => list.map((w) => code[w]));
}

const hostsOf = (hop) => `${hop.helo || '¿?'} → ${hop.by || '¿?'}`;

function timeFindings(hops) {
  const out = [];
  const dated = hops.filter((h) => h.time !== null);
  for (let i = 1; i < dated.length; i++) {
    if (dated[i].time < dated[i - 1].time - SKEW_MS) {
      out.push(finding({
        id: 'route.time-travel', detector: name, severity: 'medium',
        title: 'Un salto de la ruta tiene una hora anterior al previo',
        params: {},
        detail: 'Cada servidor añade su Received después del anterior. Una hora que retrocede más de 5 minutos suele indicar cabeceras inventadas o copiadas de otro correo.',
        evidence: `${hostsOf(dated[i - 1])} (${dated[i - 1].date}) → ${hostsOf(dated[i])} (${dated[i].date})`,
      }));
      break;
    }
  }
  if (dated.length >= 2 && dated.at(-1).time - dated[0].time > DAY_MS) {
    const hours = Math.round((dated.at(-1).time - dated[0].time) / 3600000);
    out.push(finding({
      id: 'route.slow-delivery', detector: name, severity: 'low',
      title: 'El correo tardó más de un día en llegar',
      params: { hours },
      detail: 'Un retraso tan largo puede deberse a colas de envío masivo o a cabeceras con fechas falsas.',
      evidence: `${hours} h entre el primer y el último salto`,
    }));
  }
  return out;
}

function heloMismatch(hop) {
  if (!hop?.helo) return null;
  const helo = hop.helo.toLowerCase().replace(/^\[|\]$/g, '');
  const brand = BRANDS.find((b) => isOfficialDomain(b, helo));
  if (!brand) return null;
  // Saltos internos del propio proveedor (Office 365 entre sus servidores, sin rDNS): el receptor
  // es de la misma organización que el HELO, así que no hay nada que contradecir.
  if (hop.by && registrableDomain(hop.by.toLowerCase()) === registrableDomain(helo)) return null;
  const rdns = hop.rdns && hop.rdns !== 'unknown' ? hop.rdns : '';
  if (rdns && (isOfficialDomain(brand, rdns) || registrableDomain(rdns) === registrableDomain(helo))) return null;
  return finding({
    id: 'route.helo-mismatch', detector: name, severity: 'high',
    title: `El servidor de origen dice ser de ${brand.name} y no lo es`,
    params: { brand: brand.name, helo, seen: rdns || { key: 'rule.route.no-rdns' }, ip: hop.ip ? ` (${hop.ip})` : '' },
    detail: `Al conectar se presentó como ${helo}, pero el servidor receptor vio ${rdns || 'una máquina sin nombre inverso'}${hop.ip ? ` (${hop.ip})` : ''}. El nombre de saludo lo elige el remitente.`,
    evidence: hop.raw.slice(0, 200),
    reliability: 'high',
  });
}

export function detect(email) {
  if (!email.hasHeaders) return [];
  const { hops, firstExternal, parsed } = parseRoute(email);
  if (hops.length === 0) return [];
  if (parsed === 0) {
    return [finding({
      id: 'route.unparseable', detector: name, severity: 'info',
      title: 'No se puede leer la ruta del correo',
      params: {},
      detail: 'Hay cabeceras Received, pero ninguna tiene un formato reconocible. La ruta no se ha podido analizar.',
      evidence: hops[0].raw.slice(0, 120),
      reliability: 'low',
    })];
  }
  const out = [];
  const entry = firstExternal === null ? null : hops[firstExternal];
  if (entry?.ip && isReservedIp(entry.ip)) {
    out.push(finding({
      id: 'route.private-ip-boundary', detector: name, severity: 'medium',
      title: 'El correo entró desde una IP privada',
      params: {},
      detail: 'El servidor que entregó el correo al receptor tiene una dirección privada o reservada, que no puede venir de Internet. Suele indicar un Received inventado.',
      evidence: `${hostsOf(entry)} [${entry.ip}]`,
    }));
  }
  const helo = heloMismatch(entry);
  if (helo) out.push(helo);
  out.push(...timeFindings(hops));
  if (hops.length > MAX_NORMAL_HOPS) {
    out.push(finding({
      id: 'route.too-many-hops', detector: name, severity: 'low',
      title: 'Ruta con demasiados saltos',
      params: { hops: hops.length },
      detail: `El correo pasó por ${hops.length} servidores. Lo normal son menos de diez; tantos saltos suelen indicar bucles o cabeceras de relleno.`,
      evidence: `${hops.length} cabeceras Received`,
    }));
  }
  return out;
}
