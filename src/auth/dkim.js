// DKIM (RFC 6376, RFC 8463) sin red.
// - Siempre: se lee la firma y se comprueba el hash del cuerpo (bh=), que no necesita clave.
// - Solo si el analista pega la clave pública: se verifica la firma con WebCrypto (verifyDkimSignature).
import { sha256Bytes } from '../lib/sha256.js';
import { bytesToBase64 } from '../lib/base64.js';

const MAX_SIGNATURES = 10;
const MAX_SIGNATURE_LENGTH = 8192;
const SUPPORTED = new Set(['rsa-sha256', 'ed25519-sha256']);
const REQUIRED = ['a', 'b', 'bh', 'd', 'h', 's'];
const ENCODER = new TextEncoder();

/** Lee las etiquetas de una DKIM-Signature. Devuelve null si falta alguna obligatoria. */
export function parseDkimSignature(value) {
  const tags = Object.create(null);
  for (const part of String(value ?? '').slice(0, MAX_SIGNATURE_LENGTH).split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const tag = part.slice(0, eq).trim().toLowerCase();
    if (/^[a-z][a-z0-9_]*$/.test(tag) && !(tag in tags)) tags[tag] = part.slice(eq + 1).trim();
  }
  if (REQUIRED.some((t) => !tags[t])) return null;
  const [header = 'simple', body = 'simple'] = (tags.c || 'simple/simple').toLowerCase().split('/');
  const strip = (v) => v.replace(/\s+/g, '');
  const l = tags.l != null && /^\d{1,76}$/.test(strip(tags.l)) ? Number(strip(tags.l)) : null;
  return {
    v: tags.v ?? '',
    a: tags.a.toLowerCase(),
    b: strip(tags.b),
    bh: strip(tags.bh),
    c: { header, body },
    d: tags.d.toLowerCase(),
    h: tags.h.split(':').map((x) => x.trim().toLowerCase()).filter(Boolean),
    i: tags.i ?? '',
    l,
    s: tags.s,
    t: tags.t != null ? Number(strip(tags.t)) : null,
    x: tags.x != null ? Number(strip(tags.x)) : null,
  };
}

/** Canonicalización del cuerpo (RFC 6376 §3.4.3 y §3.4.4). Devuelve siempre CRLF. */
export function canonicalizeBody(rawBody, mode) {
  let lines = String(rawBody ?? '').split(/\r?\n/);
  if (mode === 'relaxed') lines = lines.map((line) => line.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
  while (lines.length && lines.at(-1) === '') lines.pop();
  if (!lines.length) return mode === 'relaxed' ? '' : '\r\n';
  return `${lines.join('\r\n')}\r\n`;
}

/** Canonicalización de una cabecera cruda sin el CRLF final (RFC 6376 §3.4.1 y §3.4.2). */
export function canonicalizeHeader(raw, mode) {
  if (mode !== 'relaxed') return raw;
  const colon = raw.indexOf(':');
  const name = raw.slice(0, colon).replace(/[ \t]+$/, '').toLowerCase();
  const value = raw.slice(colon + 1).replace(/\r?\n/g, '').replace(/[ \t]+/g, ' ').trim();
  return `${name}:${value}`;
}

/** Bytes del cuerpo que cubre la firma, o null si l= pide más de lo que hay. */
export function signedBody(email, sig) {
  const bytes = ENCODER.encode(canonicalizeBody(email.rawBody, sig.c.body));
  if (sig.l === null) return bytes;
  return sig.l > bytes.length ? null : bytes.subarray(0, sig.l);
}

/**
 * Comprueba el hash de cuerpo de cada firma.
 * @returns {Array<{ sig, raw, bodyHashOk: boolean|null, issues: string[] }>}
 */
export function checkDkimBodies(email, { now = Date.now() } = {}) {
  return (email.headerList ?? [])
    .filter((h) => h.name === 'dkim-signature')
    .slice(0, MAX_SIGNATURES)
    .map((h) => {
      const sig = parseDkimSignature(h.value);
      if (!sig) return { sig: null, raw: h.raw, bodyHashOk: null, issues: ['malformed'] };
      const issues = [];
      if (sig.l !== null) issues.push('l-tag');
      if (sig.x !== null && sig.x * 1000 < now) issues.push('expired');
      if (sig.a === 'rsa-sha1') issues.push('rsa-sha1');
      else if (!SUPPORTED.has(sig.a)) issues.push('unknown-algorithm');
      if (!SUPPORTED.has(sig.a)) return { sig, raw: h.raw, bodyHashOk: null, issues };
      const body = signedBody(email, sig);
      const bodyHashOk = body !== null && bytesToBase64(sha256Bytes(body)) === sig.bh;
      return { sig, raw: h.raw, bodyHashOk, issues };
    });
}
