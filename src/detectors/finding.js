// Estructura común de un hallazgo.
import { techniqueFor } from '../data/mitre.js';

export const SEVERITY_POINTS = { info: 0, low: 5, medium: 15, high: 30 };
export const SEVERITY_ORDER = ['high', 'medium', 'low', 'info'];

/** Crea un hallazgo con sus puntos calculados a partir de la severidad. */
export function finding({ id, detector, severity, title, detail, evidence = '' }) {
  if (!(severity in SEVERITY_POINTS)) throw new Error(`Severidad desconocida: ${severity}`);
  return {
    id, detector, severity, points: SEVERITY_POINTS[severity], title, detail,
    evidence: String(evidence), mitre: techniqueFor(id),
  };
}
