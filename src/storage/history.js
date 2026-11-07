// Historial (spec 3.0, §2): una entrada por correo analizado, sin el correo. Deduplica por SHA-256,
// guarda como mucho 500 y valida todo lo que lee, porque la base o el fichero importado pueden venir tocados.
import { sha256 } from '../lib/sha256.js';
import { slimReport, validateEntry, safeParse } from './schema.js';

export const HISTORY_MAX = 500;
export const IMPORT_MAX_BYTES = 20 * 1024 * 1024;
export const PAGE_SIZE = 50;
const SEARCH_MIN = 3;
const SEARCH_MAX = 100;
const IOC_TYPES = ['domains', 'ips', 'urls', 'emails', 'hashes', 'sha1', 'md5'];
const FORMAT = 'history/1';

const byNewest = (a, b) => (a.savedAt < b.savedAt ? 1 : a.savedAt > b.savedAt ? -1 : 0);

function iocsOf(entry) {
  const out = [];
  for (const type of IOC_TYPES) for (const v of entry.report?.iocs?.[type] ?? []) if (typeof v === 'string') out.push([type, v]);
  return out;
}

/**
 * @param backend ver backends.js
 * @param {{now?: () => Date, uuid?: () => string, version: string}} options
 */
export function createHistory(backend, { now = () => new Date(), uuid = () => crypto.randomUUID(), version }) {
  async function valid() {
    let skipped = 0;
    const items = [];
    for (const raw of await backend.getAll('analyses')) {
      const res = validateEntry(raw);
      if (res.ok) items.push(res.entry);
      else skipped++;
    }
    return { items: items.sort(byNewest), skipped };
  }

  async function evict() {
    const count = await backend.count('analyses');
    if (count <= HISTORY_MAX) return 0;
    const all = (await backend.getAll('analyses')).sort((a, b) => -byNewest(a, b));
    const extra = all.slice(0, count - HISTORY_MAX);
    for (const e of extra) await backend.delete('analyses', e.id);
    return extra.length;
  }

  /** Guarda una entrada ya validada; si su hash existe, reutiliza su id. */
  async function store(entry) {
    const existing = await backend.getByIndex('analyses', 'sha256', entry.sha256);
    let final = existing ? { ...entry, id: existing.id } : entry;
    // Un id que ya usa otro correo (p. ej. en un fichero importado) no lo pisa: se le da uno nuevo.
    if (!existing && (await backend.get('analyses', final.id)) !== undefined) final = { ...final, id: uuid() };
    await backend.put('analyses', final);
    return final;
  }

  async function save({ kind, value, name = null, report }) {
    const res = validateEntry({
      id: uuid(), savedAt: now().toISOString(), version, kind, sha256: sha256(String(value ?? '')),
      name: name == null ? null : String(name).slice(0, 260), report: slimReport(report),
    });
    if (!res.ok) throw new Error(`no se puede guardar: ${res.error}`);
    const entry = await store(res.entry);
    return { entry, evicted: await evict() };
  }

  async function saveBatch({ entries = [], campaigns = [] }) {
    const hashes = new Map();
    let evicted = 0;
    for (const e of entries) {
      const out = await save(e);
      hashes.set(e.name, out.entry.sha256);
      evicted += out.evicted;
    }
    const clean = safeParse(JSON.stringify(campaigns.map((c) => ({ id: c.id, name: c.name, reasons: c.reasons ?? [], techniques: c.techniques ?? [], emails: (c.emails ?? []).map((k) => hashes.get(k)).filter(Boolean) }))));
    const id = uuid();
    await backend.put('batches', { id, savedAt: now().toISOString(), emails: [...hashes.values()], campaigns: clean });
    return { id, saved: hashes.size, evicted };
  }

  async function list({ level, since, technique, offset = 0, limit = PAGE_SIZE } = {}) {
    const { items, skipped } = await valid();
    const sinceIso = since ? new Date(since).toISOString() : null;
    const filtered = items.filter((e) => (!level || e.report.level === level)
      && (!sinceIso || e.savedAt >= sinceIso)
      && (!technique || (e.report.techniques ?? []).some((t) => t?.id === technique)));
    return { items: filtered.slice(offset, offset + limit), total: filtered.length, skipped };
  }

  async function get(id) {
    const raw = await backend.get('analyses', String(id));
    if (raw === undefined) return null;
    const res = validateEntry(raw);
    return res.ok ? res.entry : null;
  }

  async function searchIoc(query) {
    const q = String(query ?? '').trim().toLowerCase();
    if (q.length < SEARCH_MIN) return [];
    const hits = new Map();
    for (const e of (await valid()).items) {
      for (const [type, value] of iocsOf(e)) {
        if (!value.toLowerCase().includes(q)) continue;
        const key = `${type}|${value}`;
        if (!hits.has(key)) hits.set(key, { value, type, ids: [] });
        const ids = hits.get(key).ids;
        if (!ids.includes(e.id)) ids.push(e.id);
      }
    }
    return [...hits.values()].sort((a, b) => b.ids.length - a.ids.length || (a.value < b.value ? -1 : 1)).slice(0, SEARCH_MAX);
  }

  async function compare(idA, idB) {
    const [a, b] = [await get(idA), await get(idB)];
    if (!a || !b) return null;
    const setA = new Set(iocsOf(a).map(([, v]) => v));
    const setB = new Set(iocsOf(b).map(([, v]) => v));
    const fa = new Set(a.report.findings.map((f) => f.id));
    const fb = new Set(b.report.findings.map((f) => f.id));
    return {
      a, b,
      sharedIocs: [...setA].filter((v) => setB.has(v)),
      onlyA: [...setA].filter((v) => !setB.has(v)),
      onlyB: [...setB].filter((v) => !setA.has(v)),
      scoreDelta: b.report.score - a.report.score,
      findings: { shared: [...fa].filter((x) => fb.has(x)), onlyA: [...fa].filter((x) => !fb.has(x)), onlyB: [...fb].filter((x) => !fa.has(x)) },
    };
  }

  async function exportJson() {
    const { items } = await valid();
    return JSON.stringify({ phishlens: FORMAT, exportedAt: now().toISOString(), entries: items }, null, 2);
  }

  async function importJson(text) {
    const raw = String(text ?? '');
    if (raw.length > IMPORT_MAX_BYTES) throw new Error('El fichero pasa de 20 MB.');
    let data;
    try {
      data = safeParse(raw);
    } catch {
      throw new Error('El fichero no es JSON válido.');
    }
    if (!data || data.phishlens !== FORMAT || !Array.isArray(data.entries)) return { imported: 0, rejected: [{ index: -1, error: 'no es un historial de PhishLens' }] };
    const rejected = [];
    let imported = 0;
    for (const [index, item] of data.entries.slice(0, HISTORY_MAX).entries()) {
      const res = validateEntry(item);
      if (!res.ok) {
        rejected.push({ index, error: res.error });
        continue;
      }
      const existing = await backend.getByIndex('analyses', 'sha256', res.entry.sha256);
      if (existing && existing.savedAt >= res.entry.savedAt) continue; // se queda la más reciente
      await store(res.entry);
      imported++;
    }
    if (data.entries.length > HISTORY_MAX) rejected.push({ index: HISTORY_MAX, error: `solo se importan ${HISTORY_MAX} entradas` });
    await evict();
    return { imported, rejected };
  }

  return {
    save, saveBatch, list, get, searchIoc, compare, exportJson, importJson,
    remove: (id) => backend.delete('analyses', String(id)),
    clear: () => backend.destroy(),
    count: () => backend.count('analyses'),
  };
}
