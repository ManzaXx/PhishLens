// UUID versión 5 (RFC 9562 §5.5): SHA-1 de namespace + nombre. Determinista: mismo nombre, mismo id.
import { sha1 } from './sha1.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** UUIDv5 en minúsculas. `namespace` es un UUID; `name`, texto (se codifica en UTF-8). */
export function uuidv5(namespace, name) {
  if (!UUID.test(String(namespace))) throw new TypeError('namespace no es un UUID');
  const ns = namespace.replaceAll('-', '').match(/../g).map((h) => parseInt(h, 16));
  const text = new TextEncoder().encode(String(name));
  const bytes = new Uint8Array(16 + text.length);
  bytes.set(ns, 0);
  bytes.set(text, 16);
  const h = sha1(bytes).slice(0, 32).match(/../g).map((x) => parseInt(x, 16));
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  const hex = h.map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
