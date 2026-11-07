// URLs sin visitarlas (spec 2.3, §5.3): se desenvuelven las redirecciones que van dentro de la propia URL
// (parámetros, base64, codificación doble) y se miran sus rasgos. Nunca hay red: todo sale del texto.
import { parseUrl, registrableDomain } from '../parser/url.js';
import { toUnicode } from '../parser/punycode.js';
import { base64ToBytes } from '../lib/base64.js';
import { TRACKING_DOMAINS } from '../data/lists.js';

export const MAX_HOPS = 10;
const MAX_DECODE = 3;
const MAX_BASE64 = 11000; // ~8 KB decodificados
const MAX_PARAM = 20000;

// Parámetros que suelen llevar el destino de una redirección.
const PARAMS = ['url', 'u', 'redirect', 'redirect_uri', 'redirect_url', 'target', 'dest', 'destination', 'next', 'continue', 'goto', 'link'];

// Envoltorios conocidos: reescriben el enlace para protegerlo o medirlo; no son redirecciones abiertas.
const WRAPPERS = [
  { via: 'safelinks', host: /(^|\.)safelinks\.protection\.outlook\.com$/, params: ['url'] },
  { via: 'google', host: /^(www\.)?google\.[a-z.]+$/, path: /^\/url$/, params: ['q', 'url'] },
  { via: 'facebook', host: /^l\.facebook\.com$/, params: ['u'] },
  { via: 'linkedin', host: /^(www\.)?linkedin\.com$/, path: /^\/redir\//, params: ['url'] },
];

const isHttp = (s) => /^https?:\/\//i.test(s);

/** Entropía de Shannon en bits por carácter. */
export function shannon(text) {
  const s = String(text ?? '');
  if (!s) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h === 0 ? 0 : h;
}

/** Host tal como está escrito (antes de que `new URL` convierta 3232235777 en 192.168.1.1). */
function rawHost(raw) {
  const authority = /^https?:\/\/([^/?#\\]{0,300})/i.exec(raw)?.[1] ?? '';
  const host = authority.slice(authority.lastIndexOf('@') + 1);
  if (host.startsWith('[')) return host.slice(0, host.indexOf(']') + 1).toLowerCase();
  return host.split(':')[0].toLowerCase();
}

/** Decimal, hexadecimal, octal o con menos de cuatro partes: una IP escrita para que no lo parezca. */
function isObfuscatedIp(host) {
  if (/^\[::ffff:/i.test(host)) return true;
  const labels = host.replace(/\.$/, '').split('.');
  if (!labels.every((l) => /^(0x[0-9a-f]*|\d+)$/i.test(l))) return false;
  return labels.length !== 4 || labels.some((l) => /^0x/i.test(l) || /^0\d/.test(l));
}

/** Texto de un parámetro convertido en URL: tal cual, con codificación doble o en base64. */
function decodeTarget(value) {
  let v = String(value ?? '').trim();
  if (!v || v.length > MAX_PARAM) return null;
  for (let i = 0; i < MAX_DECODE; i++) {
    if (isHttp(v)) return { href: v, base64: false };
    if (!/^https?%3a/i.test(v)) break;
    try {
      v = decodeURIComponent(v);
    } catch {
      return null;
    }
  }
  if (isHttp(v)) return { href: v, base64: false };
  if (v.length > MAX_BASE64 || !/^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(v)) return null;
  const bytes = base64ToBytes(v.replaceAll('-', '+').replaceAll('_', '/'));
  if (!bytes) return null;
  const text = new TextDecoder().decode(bytes).trim();
  return isHttp(text) && !/[\s\0]/.test(text) ? { href: text, base64: true } : null;
}

/** El siguiente salto de `href`, o null si no lleva otra URL dentro. */
function nextHop(href) {
  let url;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  const wrapper = WRAPPERS.find((w) => w.host.test(host) && (!w.path || w.path.test(url.pathname)));
  const names = wrapper ? wrapper.params : PARAMS;
  for (const name of names) {
    let value;
    try {
      value = url.searchParams.get(name);
    } catch {
      return null;
    }
    const target = decodeTarget(value);
    if (target) return { raw: target.href, via: wrapper ? wrapper.via : target.base64 ? 'base64' : `param:${name}` };
  }
  return null;
}

const isWrapperOrTracking = (hostname) => WRAPPERS.some((w) => w.host.test(hostname)) || TRACKING_DOMAINS.has(registrableDomain(hostname));

/**
 * @returns {null | {input, final, hops: Array<{href, via}>, cycle, truncated, hostname, unicodeHost, port,
 *   entropy: {host, path}, flags: {nestedRedirect, obfuscatedIp, credentials, highEntropy, openRedirect, nonStandardPort}}}
 */
export function analyzeUrl(href) {
  const input = String(href ?? '').trim();
  const first = parseUrl(input);
  if (!first) return null;
  const raw0 = /^www\./i.test(input) ? `http://${input}` : input;
  const hops = [{ href: first.href, via: null, raw: raw0, url: first }];
  const seen = new Set([first.href]);
  let cycle = false;
  let truncated = false;
  for (;;) {
    const next = nextHop(hops.at(-1).href);
    if (!next) break;
    const parsed = parseUrl(next.raw);
    if (!parsed) break;
    if (seen.has(parsed.href)) {
      cycle = true;
      break;
    }
    if (hops.length > MAX_HOPS) {
      truncated = true;
      break;
    }
    seen.add(parsed.href);
    hops.push({ href: parsed.href, via: next.via, raw: next.raw, url: parsed });
  }

  let port = '';
  let credentials = false;
  let obfuscatedIp = false;
  let openRedirect = false;
  hops.forEach((h, i) => {
    const u = new URL(h.href);
    if (!port && u.port && u.port !== '80' && u.port !== '443') port = u.port;
    if (u.password) credentials = true;
    if (isObfuscatedIp(rawHost(h.raw))) obfuscatedIp = true;
    if (i > 0 && (h.via === 'base64' || h.via.startsWith('param:'))) {
      const outer = hops[i - 1].url;
      if (!isWrapperOrTracking(outer.hostname) && outer.registrableDomain !== h.url.registrableDomain) openRedirect = true;
    }
  });

  const last = hops.at(-1).url;
  const mainLabel = last.isIp ? '' : registrableDomain(last.hostname).split('.')[0];
  const segments = last.pathOnly.split('/').filter((s) => s.length >= 24);
  const entropy = { host: shannon(mainLabel), path: Math.max(0, ...segments.map(shannon)) };
  const tracking = isWrapperOrTracking(last.hostname);
  // Solo cuenta el host: un path aleatorio es lo normal en los enlaces de seguimiento de cualquier newsletter.
  const highEntropy = !tracking && !last.isPunycode && mainLabel.length >= 12 && entropy.host >= 3.5 && !mainLabel.includes('-');

  return {
    input,
    final: last.href,
    hops: hops.map(({ href: h, via }) => ({ href: h, via })),
    cycle,
    truncated,
    hostname: last.hostname,
    unicodeHost: toUnicode(last.hostname),
    port,
    entropy,
    flags: { nestedRedirect: hops.length - 1 >= 2, obfuscatedIp, credentials, highEntropy, openRedirect, nonStandardPort: port !== '' },
  };
}

const MAX_CHAIN = 300;

/** Un salto intermedio sin su query larga: «https://r.test/go?url=…». nextVia: cómo se sacó el siguiente. */
export function shortHop(href, nextVia) {
  const u = new URL(href);
  const name = nextVia?.startsWith('param:') ? nextVia.slice(6) : null;
  return `${u.origin}${u.pathname}${u.search ? (name ? `?${name}=…` : '?…') : ''}`;
}

/** La cadena de saltos en una línea: «a → b → c», recortada a 300 caracteres. */
export function chainText(analysis) {
  const { hops } = analysis;
  const text = hops.map((h, i) => (i < hops.length - 1 ? shortHop(h.href, hops[i + 1].via) : h.href)).join(' → ');
  return text.length > MAX_CHAIN ? `${text.slice(0, MAX_CHAIN - 1)}…` : text;
}
