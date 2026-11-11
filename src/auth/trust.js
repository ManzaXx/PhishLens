// Qué Authentication-Results son de fiar (spec 2.2, §4.2).
// Cualquiera puede escribir "dmarc=pass" en su correo: solo cuenta lo que añadió el receptor
// (o un proveedor conocido) ANTES de que el correo cruzara de otra organización.
import { parseAuthResults } from './authres.js';
import { receivingHop } from '../parser/received.js';

export { receivingHop };
import { registrableDomain } from '../parser/url.js';
import { TRUSTED_AUTHSERV } from '../data/authserv.js';

const MAX_HEADERS = 20;

const org = (host) => (host ? registrableDomain(host.toLowerCase().replace(/\.$/, '')) : '');

function inTrustedList(id) {
  return TRUSTED_AUTHSERV.some((pattern) => (pattern.startsWith('*.')
    ? id.endsWith(pattern.slice(1)) && id.length > pattern.length - 1
    : id === pattern));
}

// ARC-Authentication-Results (RFC 8617) es un Authentication-Results con "i=N;" delante. Gmail y
// Microsoft 365 lo escriben por encima de su Received de entrada aunque dejen el otro por debajo.
const ARC_INSTANCE = /^\s*i\s*=\s*\d+\s*;/i;

/**
 * Clasifica cada Authentication-Results (y ARC-Authentication-Results) del correo en tres zonas:
 * - por encima de la entrada: lo escribió el receptor; de confianza si es suyo o de un proveedor conocido.
 * - entre la entrada y el siguiente Received: ambiguo. Postfix con milters y Gmail escriben aquí el
 *   suyo, pero también es donde cae lo que el remitente puso al principio del mensaje. Sin confirmar.
 * - por debajo del siguiente Received: ya venía escrito; si imita al receptor, es falso.
 * @returns {{ receiver: string|null, boundaryIndex: number|null,
 *   headers: Array<{index, raw, parsed, trusted, forged, ambiguous, arc, why, whyRef}> }}
 */
export function classifyAuthResults(email) {
  const list = email.headerList ?? [];
  const { receiver, receiverOrg, entry, boundary, spoofedChain } = receivingHop(email);
  const boundaryIndex = entry ? entry.index : null;

  const candidates = list
    .filter((h) => h.name === 'authentication-results' || (h.name === 'arc-authentication-results' && ARC_INSTANCE.test(h.value)))
    .slice(0, MAX_HEADERS)
    .map((h) => {
      const arc = h.name === 'arc-authentication-results';
      const parsed = parseAuthResults(arc ? h.value.replace(ARC_INSTANCE, '') : h.value);
      const id = parsed.authservId;
      const claimsPass = parsed.results.some((r) => r.result === 'pass');
      const sameOrg = Boolean(receiverOrg) && org(id) === receiverOrg;
      const above = boundaryIndex !== null && h.index < boundaryIndex;
      const ambiguous = boundaryIndex !== null && !above && (!boundary || h.index < boundary.index);
      // Exchange Online escribe Authentication-Results sin authserv-id: vale si el receptor es Microsoft.
      const anonymousFromProvider = !id && !arc && inTrustedList(receiver ?? '');
      if (anonymousFromProvider) parsed.authservId = receiver;
      const trusted = above && (sameOrg || inTrustedList(id) || anonymousFromProvider);
      return { h, arc, parsed, id, claimsPass, sameOrg, above, ambiguous, trusted };
    });
  // Si el receptor ya dejó su Authentication-Results por encima, otra con su nombre por debajo no es
  // suya. El ARC no cuenta para esto: Gmail copia ahí el mismo resultado que escribe por debajo.
  const receiverWroteAbove = candidates.some((c) => c.trusted && c.sameOrg && !c.arc);
  // Lo que el receptor dijo arriba (también en ARC), método a método: una cabecera ambigua que
  // diga «pass» donde el receptor no dijo «pass» lo contradice y es falsa.
  const trustedResults = new Map();
  for (const c of candidates.filter((x) => x.trusted)) for (const r of c.parsed.results) if (!trustedResults.has(r.method)) trustedResults.set(r.method, r.result);
  const contradicts = (parsed) => parsed.results.some((r) => r.result === 'pass' && trustedResults.has(r.method) && trustedResults.get(r.method) !== 'pass');

  const headers = candidates.filter((c) => !c.arc || c.above).map(({ h, arc, parsed, id, claimsPass, sameOrg, ambiguous, trusted }) => {
    if (!receiver) return { index: h.index, raw: h.raw, parsed, trusted: false, forged: false, ambiguous: false, arc, why: 'sin ruta Received', whyRef: { code: 'auth.why.no-route', params: {} } };
    // Falsa: imita al propio receptor donde el receptor no la pudo escribir. Una cabecera de otro
    // proveedor por debajo es normal en un reenvío (Gmail → Outlook): solo queda sin confirmar.
    const unsure = ambiguous && !receiverWroteAbove && !spoofedChain && !contradicts(parsed);
    const forged = !trusted && claimsPass && sameOrg && !arc && !unsure;
    const isAmbiguous = !trusted && !forged && sameOrg && unsure;
    const why = trusted
      ? `añadida por ${id}, el servidor que recibió el correo`
      : forged
        ? `dice venir de ${id} pero estaba ya escrita cuando el correo llegó a ${receiver}${boundary ? ` desde ${boundary.by}` : ''}`
        : isAmbiguous
          ? `está justo debajo de la entrada en ${receiver}: pudo añadirla ${id} o venir ya escrita en el correo, así que no se puede confirmar`
          : `añadida por ${id || 'un servidor sin nombre'}, que no es el receptor`;
    const whyRef = trusted
      ? { code: 'auth.why.trusted', params: { id } }
      : forged
        ? { code: boundary ? 'auth.why.forged-from' : 'auth.why.forged', params: { id, receiver, from: boundary?.by ?? '' } }
        : isAmbiguous
          ? { code: 'auth.why.ambiguous', params: { id, receiver } }
          : { code: id ? 'auth.why.untrusted' : 'auth.why.untrusted-anon', params: { id: id || '' } };
    return { index: h.index, raw: h.raw, parsed, trusted, forged, ambiguous: isAmbiguous, arc, why, whyRef };
  });
  return { receiver, boundaryIndex, headers };
}
