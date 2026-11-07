// Interruptor del historial (spec 3.0, §2.1 y §2.4). Apagado no abre la base; encendido guarda cada
// análisis. Nada de esto puede romper un análisis: si IndexedDB falla, el historial se apaga y lo dice.
import { createHistory } from '../storage/history.js';
import { idbBackend } from '../storage/backends.js';
import { HISTORY_KEY, historyEnabled } from './route.js';

/**
 * @param {{storage, factory?, version: string, open?: () => Promise<Backend>}} options
 *   storage: localStorage (o null); factory: indexedDB; open: para los tests.
 */
export function createHistoryControl({ storage, factory, version, open = () => idbBackend(factory) }) {
  let history = null;
  let unavailable = false;
  let opening = null;
  const listeners = new Map();
  const emit = (event, value) => { for (const fn of listeners.get(event) ?? []) fn(value); };
  const remember = (value) => {
    try {
      storage?.setItem(HISTORY_KEY, value);
    } catch { /* sin almacenamiento, el interruptor dura la pestaña */ }
  };
  const fail = () => {
    unavailable = true;
    history = null;
    emit('unavailable');
  };

  async function connect() {
    if (history) return true;
    opening ??= (async () => {
      try {
        history = createHistory(await open(), { version });
        return true;
      } catch {
        fail();
        return false;
      } finally {
        opening = null;
      }
    })();
    return opening;
  }

  async function guard(fn) {
    if (!history) return;
    try {
      const out = await fn(history);
      const evicted = out?.evicted ?? 0;
      if (evicted) emit('evicted', evicted);
      emit('change');
    } catch {
      fail();
    }
  }

  return {
    on(event, fn) {
      if (!listeners.has(event)) listeners.set(event, []);
      listeners.get(event).push(fn);
    },
    enabled: () => !unavailable && history !== null,
    unavailable: () => unavailable,
    history: () => history,
    /** Al cargar la página: si el historial estaba encendido, abre la base. */
    async ready() {
      if (historyEnabled(storage)) await connect();
    },
    async enable() {
      unavailable = false;
      if (!(await connect())) return { ok: false, reason: 'unavailable' };
      remember('on');
      emit('change');
      return { ok: true };
    },
    disable() {
      remember('off');
      history = null;
      emit('change');
    },
    record: (input, report, name = null) => guard((h) => h.save({ kind: input.kind, value: input.value, name, report })),
    /** batch: {entries: [{key, name, report}], campaigns}; texts: clave → texto del correo. */
    recordBatch: (batch, texts) => guard((h) => h.saveBatch({
      entries: batch.entries.map((e) => ({ kind: 'eml', value: texts.get(e.key) ?? '', name: e.name, report: e.report })),
      campaigns: (batch.campaigns ?? []).map((c) => ({ ...c, emails: (c.emails ?? []).map((k) => batch.entries.find((e) => e.key === k)?.name).filter(Boolean) })),
    })),
  };
}
