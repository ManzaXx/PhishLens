import { el } from '../dom.js';
import { SEVERITY, severityKey } from './labels.js';

/** Etiqueta de gravedad en mayúsculas: GRAVE, MEDIA, LEVE o INFO. */
export function severityTag(severity) {
  const key = severityKey(severity);
  return el('span', { className: `sev sev--${key}`, text: SEVERITY.get(key).toUpperCase() });
}
