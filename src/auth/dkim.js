// DKIM (RFC 6376, RFC 8463) sin red.
// - Siempre: se lee la firma y se comprueba el hash del cuerpo (bh=), que no necesita clave.
// - Solo si el analista pega la clave pública: se verifica la firma con WebCrypto (verifyDkimSignature).
import { sha256Bytes } from '../lib/sha256.js';
import { base64ToBytes, bytesToBase64 } from '../lib/base64.js';

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

/**
 * Datos que cubre la firma (RFC 6376 §5.4.2 y §3.7): las cabeceras de h= tomadas de abajo
 * arriba, cada una canonicalizada y terminada en CRLF, y al final la propia DKIM-Signature
 * con b= vacío y sin CRLF.
 */
export function signedHeaderData(email, sig, sigRaw) {
  const pending = new Map();
  for (const h of email.headerList ?? []) {
    if (!pending.has(h.name)) pending.set(h.name, []);
    pending.get(h.name).push(h.raw);
  }
  let data = '';
  for (const name of sig.h) {
    const stack = pending.get(name);
    if (stack?.length) data += `${canonicalizeHeader(stack.pop(), sig.c.header)}\r\n`;
  }
  const unsigned = sigRaw.replace(/(;|:)([ \t\r\n]*b[ \t\r\n]*=)[^;]*/i, '$1$2');
  return data + canonicalizeHeader(unsigned, sig.c.header);
}

/** Interpreta el registro TXT de la clave: {k, p} o {error}. Acepta trozos entre comillas. */
export function parseDkimKeyRecord(txt) {
  let text = String(txt ?? '').slice(0, 8192);
  if (text.includes('"')) text = [...text.matchAll(/"([^"]*)"/g)].map((m) => m[1]).join('');
  const tags = Object.create(null);
  for (const part of text.split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).replace(/\s+/g, '');
  }
  if (!('p' in tags)) return { error: 'malformed' };
  if (tags.p === '') return { error: 'revoked' };
  const k = (tags.k || 'rsa').toLowerCase();
  if (k !== 'rsa' && k !== 'ed25519') return { error: 'unsupported' };
  const p = base64ToBytes(tags.p);
  return p && p.length ? { k, p } : { error: 'malformed' };
}

const KEY_ERRORS = { revoked: 'clave revocada', malformed: 'clave mal formada', unsupported: 'algoritmo no compatible' };

/**
 * Verifica la firma DKIM número `index` con la clave que pegó el analista.
 * Asíncrona porque usa WebCrypto; nunca lanza.
 */
export async function verifyDkimSignature(email, keyTxt, index = 0) {
  const entry = checkDkimBodies(email)[index];
  if (!entry) return { ok: false, reason: 'no hay firma DKIM', domain: '', selector: '' };
  const { sig } = entry;
  const result = (ok, reason) => ({ ok, reason, domain: sig?.d ?? '', selector: sig?.s ?? '' });
  if (!sig) return result(false, 'firma mal formada');
  if (!SUPPORTED.has(sig.a)) return result(false, 'algoritmo no compatible');
  if (entry.bodyHashOk === false) return result(false, 'el cuerpo no coincide con bh=');
  const key = parseDkimKeyRecord(keyTxt);
  if (key.error) return result(false, KEY_ERRORS[key.error]);
  if ((key.k === 'ed25519') !== (sig.a === 'ed25519-sha256')) return result(false, 'firma no válida');
  const signature = base64ToBytes(sig.b);
  if (!signature) return result(false, 'firma mal formada');
  const data = ENCODER.encode(signedHeaderData(email, sig, entry.raw));
  try {
    const subtle = globalThis.crypto.subtle;
    const ok = key.k === 'rsa'
      ? await subtle.verify('RSASSA-PKCS1-v1_5',
        await subtle.importKey('spki', key.p, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']), signature, data)
      // RFC 8463: Ed25519 firma el hash SHA-256 de los datos, no los datos.
      : await subtle.verify('Ed25519', await subtle.importKey('raw', key.p, { name: 'Ed25519' }, false, ['verify']), signature, sha256Bytes(data));
    return result(ok, ok ? 'firma válida' : 'firma no válida');
  } catch {
    return result(false, 'clave mal formada');
  }
}
