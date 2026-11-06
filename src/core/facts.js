// Cifras de la portada sacadas del código, para que no se queden viejas (spec 2.3, §5).
import { DEFAULT_DETECTORS } from './engine.js';
import { LEVELS } from './scoring.js';
import { PLAIN } from '../data/plain.js';
import { ATTACK_VERSION } from '../data/mitre.js';

export const FACTS = Object.freeze({
  detectors: DEFAULT_DETECTORS.length,
  rules: Object.keys(PLAIN).length,
  attack: ATTACK_VERSION,
});

/** Tramos de la escala de riesgo, de menor a mayor: [{min, max, label, level}]. */
export function levelLegend() {
  const asc = [...LEVELS].sort((a, b) => a.min - b.min);
  return asc.map((l, i) => ({ min: l.min, max: i + 1 < asc.length ? asc[i + 1].min - 1 : 100, label: l.label, level: l.level }));
}
