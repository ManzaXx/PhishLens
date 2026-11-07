// Entradas de lote sintéticas para los tests del grafo y las campañas.
import { rng, pick } from './rng.js';

let n = 0;
/** Una entrada {key, name, report} mínima; `email` y el resto se mezclan con lo dado. */
export function entry({ key, name, level = 'phishing', findings = [], techniques = [], email = {} } = {}) {
  n++;
  const k = key ?? `k${String(n).padStart(4, '0')}`;
  return {
    key: k,
    name: name ?? `${k}.eml`,
    report: {
      level, score: 50, findings, techniques,
      email: { from: null, replyTo: null, subject: '', links: [], attachments: [], route: [], text: '', html: '', ...email },
    },
  };
}

/** Copia barajada con semilla (Fisher-Yates). */
export function shuffle(list, seed) {
  const r = rng(seed);
  const out = [...list];
  for (let i = out.length - 1; i > 0; i--) {
    const j = pick(r, i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}
