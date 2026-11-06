// Tipo real de un fichero por sus «bytes mágicos». Nunca mira la extensión.
import { reader, latin1, startsWith } from './bytes.js';

export const TYPE_LABELS = new Map([
  ['pe', 'Ejecutable de Windows'], ['elf', 'Ejecutable de Linux'], ['zip', 'Archivo ZIP'],
  ['ole', 'Documento OLE (Office antiguo)'], ['pdf', 'PDF'], ['rtf', 'RTF'], ['iso', 'Imagen de disco ISO'],
  ['lnk', 'Acceso directo de Windows'], ['html', 'Página HTML'], ['script', 'Script'], ['unknown', 'Desconocido'],
]);

export const OLE_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const LNK_MAGIC = [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
const HTML_START = /^(?:\xEF\xBB\xBF)?\s*<(?:!doctype html|html|head|body|script)\b/i;

function type(bytes) {
  if (startsWith(bytes, 'MZ')) {
    // Un PE de verdad tiene «PE\0\0» donde apunta e_lfanew. Si el puntero cae dentro
    // y no está la firma, son dos letras sueltas («MZ Logística…»), no un ejecutable.
    const r = reader(bytes);
    const lfanew = r.u32(0x3c);
    if (lfanew === null || lfanew + 4 > bytes.length) return 'pe';
    return startsWith(bytes, 'PE\0\0', lfanew) ? 'pe' : 'unknown';
  }
  if (startsWith(bytes, '\x7FELF')) return 'elf';
  if (startsWith(bytes, 'PK\x03\x04') || startsWith(bytes, 'PK\x05\x06')) return 'zip';
  if (startsWith(bytes, OLE_MAGIC)) return 'ole';
  if (startsWith(bytes, LNK_MAGIC)) return 'lnk';
  if (startsWith(bytes, '{\\rtf')) return 'rtf';
  if ([0x8001, 0x8801, 0x9001].some((o) => startsWith(bytes, 'CD001', o))) return 'iso';
  if (startsWith(bytes, '#!')) return 'script';
  const head = latin1(bytes, 0, Math.min(bytes.length, 1024));
  // Los lectores de PDF aceptan la cabecera en cualquier punto del primer kilobyte.
  if (head.includes('%PDF-')) return 'pdf';
  if (HTML_START.test(head)) return 'html';
  return 'unknown';
}

/** `{type, label}` del contenido real. */
export function sniff(bytes) {
  const t = type(bytes);
  return { type: t, label: TYPE_LABELS.get(t) };
}
