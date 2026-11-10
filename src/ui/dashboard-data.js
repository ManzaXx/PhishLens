// Datos del panel (spec 3.0, §3): las estadísticas se calculan una vez por revisión del historial.
import { historyStats } from '../intel/stats.js';
import { HISTORY_MAX } from '../storage/history.js';

/**
 * @param control historyControl (history-control.js)
 * @param {{revision?: number, value?: object}} cache objeto que guarda el último cálculo
 * @returns {Promise<{stats}|null>} null con el historial apagado
 */
export async function dashboardData(control, cache = {}, now = new Date()) {
  if (!control.enabled()) return null;
  const rev = control.revision();
  if (cache.value && cache.revision === rev) return cache.value;
  const h = control.history();
  // Tras «Borrar todo» no hay base: el panel no la vuelve a crear solo por mirarlo. Todos los lotes:
  // la cifra de campañas no puede depender de un tope que no se ve.
  const [items, batches] = h
    ? await Promise.all([h.list({ limit: HISTORY_MAX }).then((r) => r.items), h.batches({ limit: Infinity })]).catch(() => [[], []])
    : [[], []];
  cache.revision = rev;
  cache.value = { stats: historyStats(items, { now, batches }) };
  return cache.value;
}
