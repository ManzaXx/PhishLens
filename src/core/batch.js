// Análisis de varios correos a la vez (spec 2.3, §5.2). Cada correo se analiza por separado con el
// motor de siempre y se cede el hilo entre uno y otro para que la página siga respondiendo.
import { analyzeInput } from './engine.js';
import { sha256 } from '../lib/sha256.js';
import { LIMITS } from '../lib/limits.js';

/** Identidad de un correo: el SHA-256 de su texto con los saltos de línea normalizados (no depende del nombre, del orden ni de CRLF/LF). */
export const emailKey = (text) => sha256(String(text).replace(/\r\n?/g, '\n'));

const isEmailFile = (f) => /\.(eml|txt)$/i.test(f.name ?? '') || f.type === 'message/rfc822';

// Una tarea nueva (no un microtask): solo así el navegador puede pintar y atender eventos entre correos.
const nextTask = () => new Promise((resolve) => setTimeout(resolve, 0));

const byName = (a, b) => String(a.name ?? '').localeCompare(String(b.name ?? ''), 'es') || (a.size ?? 0) - (b.size ?? 0);

/**
 * Analiza un lote de ficheros {name, size, text()} uno a uno.
 * @returns {Promise<{entries: Array<{key, name, report}>, skipped: Array<{name, reason}>, warning: string|null} | null>}
 *   null si `signal` se abortó mientras tanto.
 */
export async function analyzeBatch(files, { analyze = analyzeInput, yieldFn = nextTask, onProgress, signal } = {}) {
  const sorted = [...files].sort(byName);
  const skipped = [];
  const queue = [];
  let bytes = 0;
  for (const f of sorted) {
    if (!isEmailFile(f)) skipped.push({ name: f.name, reason: 'tipo' });
    else if ((f.size ?? 0) > LIMITS.inputBytes) skipped.push({ name: f.name, reason: 'tamano' });
    else if (queue.length >= LIMITS.batchFiles || bytes + (f.size ?? 0) > LIMITS.batchBytes) skipped.push({ name: f.name, reason: 'limite' });
    else {
      queue.push(f);
      bytes += f.size ?? 0;
    }
  }
  const limited = skipped.filter((s) => s.reason === 'limite').length;
  const entries = new Map();
  for (let i = 0; i < queue.length; i++) {
    if (signal?.aborted) return null;
    const f = queue[i];
    let text;
    try {
      text = String(await f.text());
    } catch {
      text = null;
    }
    if (signal?.aborted) return null;
    if (text === null) {
      skipped.push({ name: f.name, reason: 'error' });
    } else if (!text.trim()) {
      skipped.push({ name: f.name, reason: 'vacio' });
    } else {
      const key = emailKey(text);
      if (entries.has(key)) {
        skipped.push({ name: f.name, reason: 'duplicado' });
      } else {
        try {
          entries.set(key, { key, name: f.name, report: analyze({ kind: 'eml', value: text }) });
        } catch {
          skipped.push({ name: f.name, reason: 'error' });
        }
      }
    }
    onProgress?.(i + 1, queue.length);
    await yieldFn();
  }
  if (signal?.aborted) return null;
  const total = queue.length + limited;
  return {
    entries: [...entries.values()].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)),
    skipped,
    warning: limited ? `Se han analizado ${queue.length} de ${total} correos: el máximo es ${LIMITS.batchFiles} por lote y ${Math.round(LIMITS.batchBytes / 1024 / 1024)} MB en total.` : null,
  };
}
