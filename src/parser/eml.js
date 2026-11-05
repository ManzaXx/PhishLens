// Parser de emails en formato .eml (RFC 5322 + MIME) sin dependencias ni DOM.
import { extractUrls } from './url.js';
import { extractAnchors } from './html.js';

// Límites defensivos frente a emails construidos para agotar CPU o memoria.
export const LIMITS = { depth: 20, parts: 500, links: 200, attachments: 100 };

const KNOWN_HEADERS = new Set([
  'from', 'to', 'cc', 'subject', 'date', 'received', 'message-id', 'return-path',
  'reply-to', 'content-type', 'mime-version', 'authentication-results', 'sender',
  'delivered-to', 'dkim-signature', 'received-spf',
]);

// ---------- Decodificación ----------

function bytesToString(bytes, charset = 'utf-8') {
  try {
    return new TextDecoder(charset.toLowerCase()).decode(bytes);
  } catch {
    return new TextDecoder('utf-8').decode(bytes);
  }
}

function base64ToBytes(b64) {
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
  try {
    const bin = atob(clean);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return new Uint8Array();
  }
}

function qpToBytes(text, isHeader = false) {
  let src = isHeader ? text.replace(/_/g, ' ') : text.replace(/=\r?\n/g, '');
  const bytes = [];
  for (let i = 0; i < src.length; i++) {
    const hex = src.slice(i + 1, i + 3);
    if (src[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(hex)) {
      bytes.push(parseInt(hex, 16));
      i += 2;
    } else {
      // Caracteres ya no ASCII se codifican tal cual en UTF-8
      bytes.push(...new TextEncoder().encode(src[i]));
    }
  }
  return new Uint8Array(bytes);
}

/** Decodifica palabras codificadas RFC 2047: =?charset?B|Q?texto?= */
export function decodeWords(value) {
  return String(value)
    .replace(/(=\?[^?]+\?[BbQq]\?[^?]*\?=)\s+(?==\?[^?]+\?[BbQq]\?)/g, '$1')
    .replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_, charset, enc, text) => {
      const bytes = enc.toUpperCase() === 'B' ? base64ToBytes(text) : qpToBytes(text, true);
      return bytesToString(bytes, charset);
    });
}

function decodeBody(body, encoding, charset) {
  const enc = (encoding || '').toLowerCase().trim();
  if (enc === 'base64') return bytesToString(base64ToBytes(body), charset);
  if (enc === 'quoted-printable') return bytesToString(qpToBytes(body), charset);
  return body;
}

// ---------- Cabeceras ----------

function splitHeaderBody(raw) {
  const match = /\r?\n\r?\n/.exec(raw);
  if (!match) return { head: raw, body: '' };
  return { head: raw.slice(0, match.index), body: raw.slice(match.index + match[0].length) };
}

function parseHeaders(head) {
  const headers = new Map();
  const lines = head.split(/\r?\n/);
  let current = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && current) {
      current.value += ' ' + line.trim();
      continue;
    }
    const m = /^([!-9;-~]+):[ \t]?(.*)$/.exec(line);
    if (!m) {
      current = null;
      continue;
    }
    current = { name: m[1].toLowerCase(), value: m[2].trim() };
    if (!headers.has(current.name)) headers.set(current.name, []);
    headers.get(current.name).push(current);
  }
  const out = new Map();
  for (const [name, entries] of headers) out.set(name, entries.map((e) => decodeWords(e.value)));
  return out;
}

function looksLikeHeaders(head) {
  const first = head.split(/\r?\n/, 1)[0] ?? '';
  const m = /^([!-9;-~]+):/.exec(first);
  if (!m) return false;
  const names = [...head.matchAll(/^([!-9;-~]+):/gm)].map((x) => x[1].toLowerCase());
  return names.some((n) => KNOWN_HEADERS.has(n));
}

/** Separa "text/html; charset=utf-8; name=x" en valor y parámetros. */
function parseParams(value = '') {
  const [main, ...rest] = value.split(';');
  const params = Object.create(null);
  for (const p of rest) {
    const m = /^\s*([^=\s*]+)(\*)?\s*=\s*(?:"([^"]*)"|(\S*))/.exec(p);
    if (!m) continue;
    let v = m[3] ?? m[4] ?? '';
    if (m[2]) {
      // RFC 2231: filename*=UTF-8''nombre%20codificado
      const parts = /^([^']*)'[^']*'(.*)$/.exec(v);
      if (parts) {
        try {
          v = decodeURIComponent(parts[2]);
        } catch {
          v = parts[2];
        }
      }
    }
    params[m[1].toLowerCase()] = decodeWords(v);
  }
  return { value: main.trim().toLowerCase(), params };
}

export function parseAddress(value) {
  const v = String(value ?? '').trim();
  if (!v) return null;
  // Búsqueda manual de "Nombre <dirección>": /^(.*)<([^>]+)>$/ es cuadrático con miles de "<".
  let name = '';
  let address = v;
  const lt = v.lastIndexOf('<');
  if (v.endsWith('>') && lt >= 0 && lt < v.length - 2) {
    name = v.slice(0, lt).trim();
    if (name.length >= 2 && name.startsWith('"') && name.endsWith('"')) name = name.slice(1, -1).trim();
    address = v.slice(lt + 1, -1).trim();
  }
  address = address.toLowerCase();
  const at = address.lastIndexOf('@');
  return { name, address, domain: at >= 0 ? address.slice(at + 1) : '' };
}

// ---------- MIME ----------

function walkPart(headers, body, acc, depth = 0) {
  if (depth > LIMITS.depth || acc.parts++ > LIMITS.parts) return;
  const type = parseParams(headers.get('content-type')?.[0] ?? 'text/plain');
  const disposition = parseParams(headers.get('content-disposition')?.[0] ?? '');
  const filename = disposition.params.filename || type.params.name || '';

  if (type.value.startsWith('multipart/') && type.params.boundary) {
    const delimiter = `--${type.params.boundary}`;
    const chunks = body.split(delimiter).slice(1);
    for (const chunk of chunks) {
      if (chunk.startsWith('--')) break;
      const part = chunk.replace(/^\r?\n/, '');
      const { head, body: partBody } = splitHeaderBody(part);
      walkPart(parseHeaders(head), partBody.replace(/\r?\n$/, ''), acc, depth + 1);
    }
    return;
  }

  if (filename || disposition.value === 'attachment') {
    if (acc.attachments.length < LIMITS.attachments) acc.attachments.push({ filename: filename || '(sin nombre)', contentType: type.value });
    return;
  }

  const content = decodeBody(body, headers.get('content-transfer-encoding')?.[0], type.params.charset);
  if (type.value === 'text/html') acc.html += content;
  else if (type.value.startsWith('text/') || !headers.has('content-type')) acc.text += content;
}

function extractLinks(html, text) {
  const links = [];
  const seen = new Set();
  const add = (link) => {
    if (links.length >= LIMITS.links) return;
    const key = `${link.text}\u0000${link.href}`;
    if (seen.has(key)) return;
    seen.add(key);
    links.push(link);
  };
  for (const link of extractAnchors(html)) add(link);
  const hrefs = new Set(links.map((l) => l.href));
  for (const url of extractUrls(text)) {
    if (!hrefs.has(url)) add({ text: url, href: url });
  }
  return links;
}

function emptyEmail() {
  return {
    headers: new Map(), from: null, replyTo: null, returnPath: null, subject: '',
    text: '', html: '', links: [], attachments: [], hasHeaders: false,
  };
}

/** Parsea un email en crudo. Nunca lanza: la entrada basura se trata como texto. */
export function parseEml(raw) {
  const source = String(raw ?? '').replace(/^﻿/, '');
  const email = emptyEmail();
  const { head, body } = splitHeaderBody(source);

  if (!looksLikeHeaders(head)) {
    email.text = source.trim();
    email.links = extractLinks('', email.text);
    return email;
  }

  const headers = parseHeaders(head);
  const acc = { text: '', html: '', attachments: [], parts: 0 };
  walkPart(headers, body, acc);

  email.headers = headers;
  email.hasHeaders = true;
  email.from = parseAddress(headers.get('from')?.[0]);
  email.replyTo = parseAddress(headers.get('reply-to')?.[0]);
  email.returnPath = headers.get('return-path')?.[0]?.replace(/[<>]/g, '').trim().toLowerCase() || null;
  email.subject = headers.get('subject')?.[0] ?? '';
  email.text = acc.text;
  email.html = acc.html;
  email.attachments = acc.attachments;
  email.links = extractLinks(acc.html, acc.text);
  return email;
}

/** Email mínimo para analizar una URL suelta con los mismos detectores. */
export function emailFromUrl(url) {
  const email = emptyEmail();
  const href = String(url ?? '').trim();
  if (href) email.links = [{ text: href, href }];
  return email;
}
