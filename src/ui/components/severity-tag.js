import { el } from '../dom.js';
import { severityKey, severityLabel } from './labels.js';

/** Etiqueta de gravedad en mayúsculas: GRAVE, MEDIA, LEVE o INFO. */
export function severityTag(severity) {
  const key = severityKey(severity);
  return el('span', { className: `sev sev--${key}`, text: severityLabel(key).toUpperCase() });
}
