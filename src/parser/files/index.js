// Inspección de un adjunto: tipo real y, según el tipo, qué lleva dentro.
// Todo de solo lectura: no se descomprime ni se ejecuta nada.
import { sniff } from './magic.js';
import { readZip } from './zip.js';
import { readOle } from './ole.js';
import { scanPdf } from './pdf.js';
import { htmlSmuggling } from './html.js';

// OOXML con macros: el proyecto VBA va en un binario dentro del ZIP.
const VBA_PROJECT = /^(word|xl|ppt)\/vbaproject\.bin$/i;

/** Extensión declarada en el nombre, en minúsculas, o null. */
export function extensionOf(filename) {
  const parts = String(filename ?? '').toLowerCase().split('.');
  return parts.length > 1 && parts.at(-1).trim() ? parts.at(-1).trim() : null;
}

/**
 * `{realType, realLabel, declaredExt, partial, zip, ole, pdf, html}`.
 * Con un adjunto recortado o ilegible (`partial`) no se mira dentro.
 */
export function inspect({ filename, bytes, truncated, lossy }) {
  const { type, label } = sniff(bytes);
  const partial = Boolean(truncated || lossy);
  const out = { realType: type, realLabel: label, declaredExt: extensionOf(filename), partial, zip: null, ole: null, pdf: null, html: null };
  if (partial) return out;
  if (type === 'zip') {
    const zip = readZip(bytes);
    out.zip = { ...zip, vbaProject: zip.entries.some((e) => VBA_PROJECT.test(e.name)) };
  } else if (type === 'ole') out.ole = readOle(bytes);
  else if (type === 'pdf') out.pdf = scanPdf(bytes);
  else if (type === 'html') out.html = htmlSmuggling(bytes);
  return out;
}
