// Utilidades para descomponer URLs sin hacer ninguna petición de red.

import { PSL_ICANN, PSL_PRIVATE } from '../data/psl.js';

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

// Public Suffix List empaquetada (ADR 0006): reglas normales, comodines ("*.ck" → "ck") y excepciones.
const RULES = new Set();
const WILDCARDS = new Set();
const EXCEPTIONS = new Set();
for (const rule of `${PSL_ICANN}\n${PSL_PRIVATE}`.split('\n')) {
  if (rule.startsWith('!')) EXCEPTIONS.add(rule.slice(1));
  else if (rule.startsWith('*.')) WILDCARDS.add(rule.slice(2));
  else if (rule) RULES.add(rule);
}
// Ninguna regla de la PSL tiene más de 5 etiquetas: no hace falta mirar más allá (y así es lineal).
const MAX_DEPTH = 8;

/** Nombre en minúsculas, sin punto final y con los IDN en punycode (como los da new URL). */
function normalizeHost(hostname) {
  let host = String(hostname ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (/[^\x00-\x7f]/.test(host)) {
    try {
      host = new URL(`http://${host}/`).hostname;
    } catch {
      // Un nombre que el navegador no acepta se compara tal cual.
    }
  }
  return host;
}

function publicSuffixLength(labels) {
  const n = labels.length;
  for (let i = Math.max(0, n - MAX_DEPTH); i < n; i++) {
    const suffix = labels.slice(i).join('.');
    if (EXCEPTIONS.has(suffix)) return n - i - 1;
    if (RULES.has(suffix) || (i + 1 < n && WILDCARDS.has(labels.slice(i + 1).join('.')))) return n - i;
  }
  return 1; // Regla por defecto "*": el TLD.
}

const cache = new Map();
const CACHE_MAX = 5000;

/**
 * Dominio organizativo según la PSL (ICANN y privada), en punycode; null si no lo hay (un sufijo
 * público, un nombre vacío o con etiquetas vacías). Es la semántica de la batería oficial de la PSL.
 */
export function organizationalDomain(hostname) {
  if (hostname === null || hostname === undefined) return null;
  const host = normalizeHost(hostname);
  if (cache.has(host)) return cache.get(host);
  let result = null;
  if (host && !host.startsWith('.')) {
    const labels = host.split('.');
    if (!labels.some((l) => l === '')) {
      const ps = publicSuffixLength(labels);
      result = labels.length > ps ? labels.slice(labels.length - ps - 1).join('.') : null;
    }
  }
  if (cache.size >= CACHE_MAX) cache.clear();
  cache.set(host, result);
  return result;
}

/**
 * Dominio registrable: "login.bbc.co.uk" -> "bbc.co.uk", "a.github.io" -> "a.github.io".
 * Si no lo hay (una IP, "localhost", un sufijo público) devuelve el nombre normalizado: nunca null.
 */
export function registrableDomain(hostname) {
  const host = normalizeHost(hostname);
  if (!host || IPV4.test(host) || host.startsWith('[')) return host;
  return organizationalDomain(host) ?? host;
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
    pathOnly: url.pathname,
    registrableDomain: isIp ? hostname : registrableDomain(hostname),
    tld: isIp ? '' : labels.at(-1),
    isIp,
    // "http://paypal.com@evil.xyz" -> el navegador va a evil.xyz
    hasAt: url.username !== '' || url.password !== '',
    isPunycode: labels.some((l) => l.startsWith('xn--')),
  };
}

const URL_IN_TEXT = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;

const TRAILING = new Set(['.', ',', ';', ':', '!', '?']);

// Recorte manual: /[.,;:!?]+$/ es cuadrático con miles de puntos seguidos.
function trimTrailing(s) {
  let end = s.length;
  while (end > 0 && TRAILING.has(s[end - 1])) end--;
  return s.slice(0, end);
}

/** Extrae URLs de un texto plano, quitando la puntuación final. */
export function extractUrls(text) {
  const found = String(text ?? '').match(URL_IN_TEXT) ?? [];
  return found.map((u) => {
    const clean = trimTrailing(u);
    // Quita paréntesis de cierre sin pareja de apertura (contando una sola vez: lineal)
    let open = 0;
    let close = 0;
    for (const ch of clean) {
      if (ch === '(') open++;
      else if (ch === ')') close++;
    }
    let end = clean.length;
    while (close > open && clean[end - 1] === ')') {
      end--;
      close--;
    }
    return trimTrailing(clean.slice(0, end));
  });
}

// Servicios que envuelven el enlace real en un parámetro de la URL.
const WRAPPERS = [
  { host: /(^|\.)safelinks\.protection\.outlook\.com$/, param: 'url' },
  { host: /^(www\.)?google\.[a-z.]+$/, path: /^\/url$/, param: 'q' },
  { host: /^l\.facebook\.com$/, param: 'u' },
  { host: /^(www\.)?linkedin\.com$/, path: /^\/redir\//, param: 'url' },
];

/** Devuelve la URL real si `href` es un envoltorio conocido (Safe Links, Google...), o null. */
export function unwrapUrl(href) {
  let url;
  try {
    url = new URL(String(href ?? ''));
  } catch {
    return null;
  }
  for (const w of WRAPPERS) {
    if (!w.host.test(url.hostname) || (w.path && !w.path.test(url.pathname))) continue;
    const inner = url.searchParams.get(w.param);
    if (inner && /^https?:\/\//i.test(inner)) return inner;
  }
  return null;
}
