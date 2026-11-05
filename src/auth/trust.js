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

/**
 * Clasifica cada Authentication-Results del correo.
 * @returns {{ receiver: string|null, boundaryIndex: number|null,
 *   headers: Array<{index, raw, parsed, trusted, forged, why}> }}
 */
export function classifyAuthResults(email) {
  const list = email.headerList ?? [];
  const { receiver, receiverOrg, entry, boundary } = receivingHop(email);
  const boundaryIndex = entry ? entry.index : null;

  const headers = list
    .filter((h) => h.name === 'authentication-results')
    .slice(0, MAX_HEADERS)
    .map((h) => {
      const parsed = parseAuthResults(h.value);
      const id = parsed.authservId;

      const claimsPass = parsed.results.some((r) => r.result === 'pass');
      const sameOrg = Boolean(receiverOrg) && org(id) === receiverOrg;
      if (!receiver) return { index: h.index, raw: h.raw, parsed, trusted: false, forged: false, why: 'sin ruta Received' };
      const aboveBoundary = boundaryIndex !== null && h.index < boundaryIndex;
      // Exchange Online escribe Authentication-Results sin authserv-id: vale si el receptor es Microsoft.
      const anonymousFromProvider = !id && inTrustedList(receiver);
      if (anonymousFromProvider) parsed.authservId = receiver;
      const trusted = aboveBoundary && (sameOrg || inTrustedList(id) || anonymousFromProvider);
      // Falsa: imita al propio receptor por debajo de la frontera. Una cabecera de otro proveedor
      // por debajo es normal en un reenvío (Gmail → Outlook): solo queda sin confirmar.
      const forged = !trusted && claimsPass && sameOrg;
      const why = trusted
        ? `añadida por ${id}, el servidor que recibió el correo`
        : forged
          ? `dice venir de ${id} pero estaba ya escrita cuando el correo llegó a ${receiver}${boundary ? ` desde ${boundary.by}` : ''}`
          : `añadida por ${id || 'un servidor sin nombre'}, que no es el receptor`;
      return { index: h.index, raw: h.raw, parsed, trusted, forged, why };
    });
  return { receiver, boundaryIndex, headers };
}
