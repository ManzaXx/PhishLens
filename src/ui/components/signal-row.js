import { el } from '../dom.js';
import { severityKey, severityLabel } from './labels.js';

/** Fila del modo sencillo: la señal en lenguaje llano y su gravedad en texto (el punto de color solo acompaña). */
export function signalRow(f) {
  const key = severityKey(f.severity);
  return el('li', { className: `signal sev-${key}` },
    el('span', { className: 'signal__dot', attrs: { 'aria-hidden': 'true' } }),
    el('span', { className: 'signal__text', text: f.plain || f.title }),
    el('span', { className: 'signal__sev', text: severityLabel(key) }));
}
