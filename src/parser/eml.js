// Parser de emails en formato .eml (RFC 5322 + MIME) sin dependencias ni DOM.
import { extractUrls } from './url.js';
import { extractAnchors } from './html.js';
import { LIMITS } from '../lib/limits.js';
import { sha256 } from '../lib/sha256.js';
import { sha1 } from '../lib/sha1.js';
import { md5 } from '../lib/md5.js';
import { inspect } from './files/index.js';

export { LIMITS };

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

/**
 * Decodifica base64 de forma tolerante: conserva el prefijo válido y avisa (`lossy`)
 * si había caracteres extraños, relleno en mitad del texto o un último carácter suelto.
 * Los espacios y saltos de línea son normales y no cuentan como pérdida.
 */
function decodeBase64(b64) {
  const compact = String(b64).replace(/[\s]/g, '');
  let clean = compact.replace(/[^A-Za-z0-9+/]/g, '');
  let lossy = !/^[A-Za-z0-9+/]*={0,2}$/.test(compact);
  if (clean.length % 4 === 1) {
    clean = clean.slice(0, -1);
    lossy = true;
  }
  try {
    const bin = atob(clean);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return { bytes, lossy };
  } catch {
    return { bytes: new Uint8Array(), lossy: true };
  }
}

function base64ToBytes(b64) {
  return decodeBase64(b64).bytes;
}

const ENCODER = new TextEncoder();
const HEX = (c) => (c >= 48 && c <= 57 ? c - 48 : c >= 65 && c <= 70 ? c - 55 : c >= 97 && c <= 102 ? c - 87 : -1);

/** Quoted-printable a bytes en tiempo lineal y sin crear objetos por carácter. */
function qpToBytes(text, isHeader = false) {
  const src = isHeader ? text.replace(/_/g, ' ') : text.replace(/=\r?\n/g, '');
  const out = new Uint8Array(src.length * 3);
  let n = 0;
  for (let i = 0; i < src.length; i++) {
    const c = src.charCodeAt(i);
    if (c === 61 && i + 2 < src.length && HEX(src.charCodeAt(i + 1)) >= 0 && HEX(src.charCodeAt(i + 2)) >= 0) {
      out[n++] = HEX(src.charCodeAt(i + 1)) * 16 + HEX(src.charCodeAt(i + 2));
      i += 2;
    } else if (c < 0x80) {
      out[n++] = c;
    } else {
      // Caracteres no ASCII (ya decodificados por el lector de ficheros) se codifican en UTF-8.
      const pair = c >= 0xd800 && c <= 0xdbff && i + 1 < src.length;
      n += ENCODER.encodeInto(src.slice(i, pair ? i + 2 : i + 1), out.subarray(n)).written;
      if (pair) i++;
    }
  }
  return out.slice(0, n);
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

/**
 * Parsea las cabeceras. Si se pasa `list`, añade cada cabecera en orden con su texto
 * crudo (plegado y saltos de línea intactos): DKIM y la detección de duplicados lo necesitan.
 */
const KEY_HEADERS = new Set([
  'from', 'sender', 'reply-to', 'return-path', 'to', 'subject', 'date', 'message-id', 'mime-version',
  'content-type', 'content-transfer-encoding', 'content-disposition',
  'authentication-results', 'arc-authentication-results', 'dkim-signature', 'received',
]);
const KEY_HEADERS_MAX = 200;

function parseHeaders(head, list = null, acc = null) {
  const headers = new Map();
  const tokens = head.split(/(\r?\n)/);
  const ordered = [];
  let current = null;
  const cap = (text) => {
    if (text.length <= LIMITS.headerBytes) return text;
    if (acc) note(acc, 'limit.header-bytes', `Alguna cabecera supera ${LIMITS.headerBytes} caracteres; se ha recortado.`, { max: LIMITS.headerBytes });
    return text.slice(0, LIMITS.headerBytes);
  };
  for (let i = 0; i < tokens.length; i += 2) {
    const line = tokens[i];
    if (/^[ \t]/.test(line) && current) {
      if (current.value.length < LIMITS.headerBytes) {
        current.value = cap(`${current.value} ${line.trim()}`);
        current.raw = cap(current.raw + tokens[i - 1] + line);
      } else if (acc) note(acc, 'limit.header-bytes', `Alguna cabecera supera ${LIMITS.headerBytes} caracteres; se ha recortado.`, { max: LIMITS.headerBytes });
      continue;
    }
    // Se mira solo el principio de la línea: el nombre nunca es largo y el valor se recorta.
    const m = /^([!-9;-~]{1,200}):[ \t]?/.exec(line);
    // Pasado el límite se siguen leyendo solo las cabeceras que cambian el veredicto, para que
    // cientos de cabeceras de relleno no escondan el Content-Type o el From.
    if (ordered.length >= LIMITS.headers) {
      if (acc) note(acc, 'limit.headers', `Más de ${LIMITS.headers} cabeceras; del resto solo se han leído las importantes.`, { max: LIMITS.headers });
      if (!m || !KEY_HEADERS.has(m[1].toLowerCase()) || ordered.length >= LIMITS.headers + KEY_HEADERS_MAX) {
        current = null;
        continue;
      }
    }
    if (!m) {
      if (acc && line.trim()) note(acc, 'mime.header-without-colon', 'Hay una línea en las cabeceras sin «:». PhishLens la ignora y sigue leyendo; otros programas darían las cabeceras por terminadas ahí.');
      current = null;
      continue;
    }
    const value = cap(line.slice(m[0].length));
    current = { name: m[1].toLowerCase(), value: value.trim(), raw: cap(line) };
    ordered.push(current);
    if (!headers.has(current.name)) headers.set(current.name, []);
    headers.get(current.name).push(current);
  }
  const out = new Map();
  for (const [name, entries] of headers) out.set(name, entries.map((e) => decodeWords(e.value)));
  if (list) {
    for (const e of ordered) list.push({ name: e.name, value: decodeWords(e.value), raw: e.raw, index: list.length });
  }
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

// params: valores neutros para que la interfaz traduzca el aviso (note.<code>).
function note(acc, code, detail, params = {}) {
  if (acc.noted.has(code)) return;
  acc.noted.add(code);
  acc.notes.push({ code, detail, params });
}

/**
 * Bytes reales de un adjunto según su codificación de transferencia.
 * `lossy` indica que el resultado no es fiel al fichero original y su hash engañaría.
 */
function attachmentBytes(body, encoding) {
  const enc = (encoding || '').toLowerCase().trim();
  if (enc === 'base64') {
    // Solo se decodifica lo que cabe en el límite; el tamaño real se calcula sin decodificar.
    const compact = String(body).replace(/\s/g, '');
    // Sin regex: /=*$/ retrocede en tiempo cuadrático ante una racha larga de «=».
    const padding = compact.endsWith('==') ? 2 : compact.endsWith('=') ? 1 : 0;
    const size = Math.max(0, Math.floor((compact.length * 3) / 4) - Math.min(2, padding));
    const needed = Math.ceil((LIMITS.attachmentBytes + 1) / 3) * 4;
    if (size > LIMITS.attachmentBytes && compact.length > needed) {
      const { bytes, lossy } = decodeBase64(compact.slice(0, needed));
      return { bytes, lossy, size, code: 'mime.bad-base64' };
    }
    return { ...decodeBase64(body), code: 'mime.bad-base64' };
  }
  if (enc === 'quoted-printable') return { bytes: qpToBytes(body), lossy: false };
  // 7bit, 8bit o binary: el texto ya pasó por el decodificador UTF-8 del navegador, así que
  // un carácter por encima de U+00FF significa que los bytes originales no se pueden recuperar.
  const bytes = new Uint8Array(body.length);
  let lossy = false;
  for (let i = 0; i < body.length; i++) {
    const c = body.charCodeAt(i);
    if (c > 0xff) lossy = true;
    bytes[i] = c & 0xff;
  }
  return { bytes, lossy, code: 'mime.lossy-attachment' };
}

function walkPart(headers, body, acc, depth = 0) {
  if (depth > LIMITS.depth) {
    note(acc, 'limit.depth', `Más de ${LIMITS.depth} niveles de partes MIME anidadas; el resto no se ha analizado.`, { max: LIMITS.depth });
    return;
  }
  if (acc.parts++ > LIMITS.parts) {
    note(acc, 'limit.parts', `Más de ${LIMITS.parts} partes MIME; el resto no se ha analizado.`, { max: LIMITS.parts });
    return;
  }
  if ((headers.get('content-type')?.length ?? 0) > 1) {
    note(acc, 'mime.duplicate-content-type', 'Una parte tiene dos Content-Type. PhishLens usa el primero; otro programa podría usar el otro y mostrar un contenido distinto.');
  }
  const type = parseParams(headers.get('content-type')?.[0] ?? 'text/plain');
  const disposition = parseParams(headers.get('content-disposition')?.[0] ?? '');
  const filename = disposition.params.filename || type.params.name || '';

  if (type.value.startsWith('multipart/') && type.params.boundary) {
    const boundary = type.params.boundary;
    if (acc.boundaries.has(boundary)) note(acc, 'mime.boundary-reuse', `El boundary "${boundary.slice(0, 70)}" se repite en dos niveles. Cada programa puede cortar las partes por un sitio distinto.`, { boundary: boundary.slice(0, 70) });
    acc.boundaries.add(boundary);
    const delimiter = `--${boundary}`;
    // RFC 2046: el delimitador solo cuenta al principio de una línea.
    const pieces = body.split(delimiter);
    const chunks = [];
    for (let i = 1; i < pieces.length; i++) {
      const before = pieces[i - 1];
      const atLineStart = i === 1 ? before === '' || before.endsWith('\n') : before.endsWith('\n');
      if (atLineStart || chunks.length === 0) chunks.push(pieces[i]);
      else {
        note(acc, 'mime.boundary-in-content', `El texto "${delimiter.slice(0, 70)}" aparece en mitad de una línea. PhishLens no corta ahí; otro programa podría hacerlo.`, { text: delimiter.slice(0, 70) });
        chunks[chunks.length - 1] += delimiter + pieces[i];
      }
    }
    let closed = false;
    for (const chunk of chunks) {
      if (chunk.startsWith('--')) {
        closed = true;
        break;
      }
      const part = chunk.replace(/^\r?\n/, '');
      const { head, body: partBody } = splitHeaderBody(part);
      walkPart(parseHeaders(head, null, acc), partBody.replace(/\r?\n$/, ''), acc, depth + 1);
    }
    if (!closed) note(acc, 'mime.unterminated-multipart', `La parte multipart con boundary "${type.params.boundary.slice(0, 70)}" no tiene delimitador de cierre.`, { boundary: type.params.boundary.slice(0, 70) });
    return;
  }

  if (filename || disposition.value === 'attachment') {
    if (acc.attachments.length >= LIMITS.attachments) {
      note(acc, 'limit.attachments', `Más de ${LIMITS.attachments} adjuntos; el resto no se ha analizado.`, { max: LIMITS.attachments });
      return;
    }
    const { bytes: all, lossy, code, size: realSize } = attachmentBytes(body, headers.get('content-transfer-encoding')?.[0]);
    if (lossy) {
      note(acc, code, code === 'mime.bad-base64'
        ? 'Algún adjunto tiene base64 corrupto o truncado; se conserva lo legible pero no se calcula su hash.'
        : 'Algún adjunto 8bit no se puede reconstruir byte a byte; no se calcula su hash.');
    }
    const truncated = (realSize ?? all.length) > LIMITS.attachmentBytes;
    if (truncated) note(acc, 'limit.attachment-bytes', `Algún adjunto supera ${LIMITS.attachmentBytes} bytes; se ha recortado y no se calcula su hash.`, { max: LIMITS.attachmentBytes });
    const bytes = truncated ? all.slice(0, LIMITS.attachmentBytes) : all;
    const attachment = {
      filename: filename || '(sin nombre)',
      contentType: type.value,
      size: realSize ?? all.length,
      bytes,
      truncated,
      lossy: Boolean(lossy),
      ...hashes(bytes, truncated || lossy || bytes.length === 0),
    };
    attachment.inspection = inspect(attachment);
    acc.attachments.push(attachment);
    return;
  }

  if (type.value === 'message/rfc822') {
    note(acc, 'mime.nested-message', 'Hay un correo dentro de otro (message/rfc822). PhishLens no lo analiza por separado: guárdalo y analízalo aparte.');
    return;
  }
  const content = decodeBody(body, headers.get('content-transfer-encoding')?.[0], type.params.charset);
  if (type.value === 'text/html' && type.params.charset) {
    const meta = /<meta[^>]{0,200}charset=["']?([\w-]{1,40})/i.exec(content.slice(0, 4096))?.[1];
    if (meta && meta.toLowerCase() !== type.params.charset.toLowerCase()) {
      note(acc, 'mime.charset-conflict', `La cabecera dice ${type.params.charset} pero el HTML dice ${meta}. PhishLens usa el de la cabecera; un navegador podría usar el otro.`, { header: type.params.charset, meta });
    }
  }
  if (type.value === 'text/html') acc.html += content;
  else if (type.value.startsWith('text/') || !headers.has('content-type')) acc.text += content;
}

// Un hash parcial, deformado o del fichero vacío engañaría como IOC.
function hashes(bytes, skip) {
  if (skip) return { sha256: null, sha1: null, md5: null };
  return { sha256: sha256(bytes), sha1: sha1(bytes), md5: md5(bytes) };
}

function extractLinks(html, text, acc = null) {
  const links = [];
  const seen = new Set();
  const add = (link) => {
    if (links.length >= LIMITS.links) {
      if (acc) note(acc, 'limit.links', `Más de ${LIMITS.links} enlaces; el resto no se ha analizado.`, { max: LIMITS.links });
      return;
    }
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
    headerList: [], rawBody: '', parseNotes: [],
  };
}

/** Parsea un email en crudo. Nunca lanza: la entrada basura se trata como texto. */
export function parseEml(raw) {
  const full = String(raw ?? '').replace(/^\uFEFF/, '');
  const source = full.length > LIMITS.inputBytes ? full.slice(0, LIMITS.inputBytes) : full;
  const email = emptyEmail();
  const { head, body } = splitHeaderBody(source);

  if (!looksLikeHeaders(head)) {
    email.text = source.trim();
    email.links = extractLinks('', email.text);
    return email;
  }

  const acc = { text: '', html: '', attachments: [], parts: 0, notes: [], noted: new Set(), boundaries: new Set() };
  if (source !== full) note(acc, 'limit.input-bytes', `La entrada supera ${LIMITS.inputBytes} caracteres; solo se ha analizado el principio.`, { max: LIMITS.inputBytes });
  const headerList = [];
  const headers = parseHeaders(head, headerList, acc);
  if (body.length > LIMITS.rawBytes) note(acc, 'limit.raw-bytes', `El cuerpo supera ${LIMITS.rawBytes} bytes; solo se conserva el principio para las comprobaciones de integridad.`);
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
  email.links = extractLinks(acc.html, acc.text, acc);
  email.headerList = headerList;
  email.rawBody = body.slice(0, LIMITS.rawBytes);
  email.parseNotes = acc.notes;
  return email;
}

/** Email mínimo para analizar una URL suelta con los mismos detectores. */
export function emailFromUrl(url) {
  const email = emptyEmail();
  const href = String(url ?? '').trim();
  if (href) email.links = [{ text: href, href }];
  return email;
}
