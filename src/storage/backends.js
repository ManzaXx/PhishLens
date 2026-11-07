// Backends del historial (spec 3.0, §2.1): la lógica de history.js no conoce IndexedDB.
// Backend = { put, get, getAll, getByIndex, delete, clear, count, destroy }, todo asíncrono.
export const DB_NAME = 'phishlens';
export const DB_VERSION = 1;
export const STORES = Object.freeze(['analyses', 'batches']);

/** En memoria, para los tests: guarda copias, como haría IndexedDB. */
export function memoryBackend() {
  const stores = new Map(STORES.map((s) => [s, new Map()]));
  const of = (store) => {
    const map = stores.get(store);
    if (!map) throw new Error(`almacén desconocido: ${store}`);
    return map;
  };
  return {
    async put(store, value) { of(store).set(value.id, structuredClone(value)); },
    async get(store, id) { const v = of(store).get(id); return v === undefined ? undefined : structuredClone(v); },
    async getAll(store) { return [...of(store).values()].map((v) => structuredClone(v)); },
    async getByIndex(store, index, value) {
      const v = [...of(store).values()].find((x) => x?.[index] === value);
      return v === undefined ? undefined : structuredClone(v);
    },
    async delete(store, id) { of(store).delete(id); },
    async clear(store) { of(store).clear(); },
    async count(store) { return of(store).size; },
    async destroy() { for (const map of stores.values()) map.clear(); },
  };
}

const request = (req) => new Promise((resolve, reject) => {
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error ?? new Error('IndexedDB'));
});

/** Sobre IndexedDB real. `factory` es globalThis.indexedDB; lanza si no se puede abrir. */
export async function idbBackend(factory) {
  if (!factory || typeof factory.open !== 'function') throw new Error('IndexedDB no está disponible');
  const open = factory.open(DB_NAME, DB_VERSION);
  open.onupgradeneeded = () => {
    const db = open.result;
    if (!db.objectStoreNames.contains('analyses')) {
      const s = db.createObjectStore('analyses', { keyPath: 'id' });
      s.createIndex('savedAt', 'savedAt');
      s.createIndex('sha256', 'sha256', { unique: true });
      s.createIndex('level', 'report.level');
    }
    if (!db.objectStoreNames.contains('batches')) db.createObjectStore('batches', { keyPath: 'id' });
  };
  let db = await request(open);
  // Otra pestaña pide borrar la base: se cierra esta conexión para no bloquearla.
  db.onversionchange = () => {
    db?.close();
    db = null;
  };
  const run = (store, mode, fn) => {
    if (!db) return Promise.reject(new Error('el historial está cerrado'));
    const tx = db.transaction(store, mode);
    const result = request(fn(tx.objectStore(store)));
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB'));
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB: transacción abortada'));
    });
  };
  return {
    put: (store, value) => run(store, 'readwrite', (s) => s.put(value)).then(() => undefined),
    get: (store, id) => run(store, 'readonly', (s) => s.get(id)),
    getAll: (store) => run(store, 'readonly', (s) => s.getAll()),
    getByIndex: (store, index, value) => run(store, 'readonly', (s) => s.index(index).get(value)),
    delete: (store, id) => run(store, 'readwrite', (s) => s.delete(id)).then(() => undefined),
    clear: (store) => run(store, 'readwrite', (s) => s.clear()).then(() => undefined),
    count: (store) => run(store, 'readonly', (s) => s.count()),
    async destroy() {
      db?.close();
      db = null;
      await request(factory.deleteDatabase(DB_NAME));
    },
  };
}
