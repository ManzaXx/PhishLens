// Utilidades para descomponer URLs sin hacer ninguna petición de red.

const SECOND_LEVEL = new Set(['co', 'com', 'org', 'gob', 'gov', 'net', 'edu', 'ac']);
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Dominio registrable aproximado: "login.bbc.co.uk" -> "bbc.co.uk". */
export function registrableDomain(hostname) {
  const labels = String(hostname).toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const last = labels.at(-1);
  const second = labels.at(-2);
  const take = last.length === 2 && SECOND_LEVEL.has(second) ? 3 : 2;
  return labels.slice(-take).join('.');
}

/** Parsea una URL de un email. Devuelve null si no es http(s). */
export function parseUrl(raw) {
  let value = String(raw ?? '').trim();
  if (!value) return null;
  if (/^www\./i.test(value)) value = `http://${value}`;
  if (!/^https?:\/\//i.test(value)) return null;

  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const hostname = url.hostname.toLowerCase();
  if (!hostname) return null;

  const isIp = IPV4.test(hostname) || hostname.startsWith('[');
  const labels = hostname.split('.');
  return {
    href: url.href,
    protocol: url.protocol.replace(':', ''),
    host: url.host,
    hostname,
    path: url.pathname + url.search,
    registrableDomain: isIp ? hostname : registrableDomain(hostname),
    tld: isIp ? '' : labels.at(-1),
    isIp,
    // "http://paypal.com@evil.xyz" -> el navegador va a evil.xyz
    hasAt: url.username !== '' || url.password !== '',
    isPunycode: labels.some((l) => l.startsWith('xn--')),
  };
}

const URL_IN_TEXT = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;

/** Extrae URLs de un texto plano, quitando la puntuación final. */
export function extractUrls(text) {
  const found = String(text ?? '').match(URL_IN_TEXT) ?? [];
  return found.map((u) => {
    let clean = u.replace(/[.,;:!?]+$/, '');
    // Paréntesis de cierre sin su pareja de apertura
    while (clean.endsWith(')') && (clean.match(/\(/g) ?? []).length < (clean.match(/\)/g) ?? []).length) {
      clean = clean.slice(0, -1).replace(/[.,;:!?]+$/, '');
    }
    return clean;
  });
}
