// Pistas de una campaña en lenguaje llano; sin DOM, para el panel y para guardar el lote en el historial.
import { defang } from '../intel/ioc.js';

/** La pista en lenguaje llano. hashNames: sha256 -> nombre del adjunto. */
export function reasonText(r, hashNames) {
  if (r.type === 'sender-domain') return `Mismo dominio de envío: ${defang(r.value)}`;
  if (r.type === 'entry-ip') return `Misma IP de entrada: ${defang(r.value)}`;
  if (r.type === 'link-domain') return `Mismo dominio en los enlaces: ${defang(r.value)}`;
  if (r.type === 'sha256') return `Mismo adjunto: ${hashNames.get(r.value) ?? 'sin nombre'} (SHA-256 ${r.value.slice(0, 12)}…)`;
  return `Misma plantilla: ${Math.round(Number(r.value) * 100)} % parecida`;
}

/** sha256 -> nombre del adjunto, sacado de los nodos del grafo del lote. */
export const hashNames = (batch) => new Map((batch?.graph?.nodes ?? []).filter((n) => n.type === 'hash').map((n) => [n.value, n.label]));
