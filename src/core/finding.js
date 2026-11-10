// Estructura común de un hallazgo.
import { techniquesFor } from '../data/mitre.js';
import { own } from '../lib/text.js';
import { plainFor } from '../data/plain.js';

export const SEVERITY_POINTS = { info: 0, low: 5, medium: 15, high: 30 };
export const SEVERITY_ORDER = ['high', 'medium', 'low', 'info'];

/** Categorías de riesgo (spec 2.2, §7.1). */
export const CATEGORIES = ['authentication', 'sender', 'links', 'attachments', 'language', 'infrastructure'];
/** Probabilidad de que la señal no sea un falso positivo. */
export const RELIABILITY = ['high', 'medium', 'low'];
/** De dónde sale la señal: comprobada por PhishLens, leída en una cabecera, deducida o imposible de comprobar sin red. */
export const PROVENANCE = ['verified', 'declared', 'inferred', 'unverifiable'];
/** 'trust' = evidencia a favor de que el correo es legítimo. */
export const POLARITY = ['risk', 'trust'];

const FALLBACK = Object.freeze({ category: 'infrastructure', reliability: 'low', provenance: 'inferred' });

export const DETECTOR_DEFAULTS = Object.freeze({
  auth: { category: 'authentication', reliability: 'medium', provenance: 'declared' },
  sender: { category: 'sender', reliability: 'high', provenance: 'inferred' },
  lookalike: { category: 'sender', reliability: 'high', provenance: 'inferred' },
  links: { category: 'links', reliability: 'medium', provenance: 'inferred' },
  html: { category: 'links', reliability: 'medium', provenance: 'inferred' },
  attachments: { category: 'attachments', reliability: 'high', provenance: 'inferred' },
  language: { category: 'language', reliability: 'low', provenance: 'inferred' },
  headers: { category: 'infrastructure', reliability: 'low', provenance: 'inferred' },
  route: { category: 'infrastructure', reliability: 'medium', provenance: 'inferred' },
  mime: { category: 'infrastructure', reliability: 'medium', provenance: 'inferred' },
  custom: { category: 'infrastructure', reliability: 'medium', provenance: 'declared' },
  input: { ...FALLBACK },
});

function oneOf(list, value, label) {
  if (!list.includes(value)) throw new Error(`${label} desconocida: ${value}`);
  return value;
}

/** Crea un hallazgo. Los campos que no se indican toman el valor por defecto de su detector. */
export function finding({ id, detector, severity, title, detail, evidence = '', category, reliability, provenance, polarity, brand = null }) {
  if (own(SEVERITY_POINTS, severity) === undefined) throw new Error(`Severidad desconocida: ${severity}`);
  const defaults = own(DETECTOR_DEFAULTS, detector) ?? FALLBACK;
  const techniques = techniquesFor(id);
  const mitre = techniques[0] ?? null;
  return {
    id, detector, severity, points: SEVERITY_POINTS[severity], title, plain: plainFor(id, brand, title), detail,
    evidence: String(evidence), mitre,
    category: oneOf(CATEGORIES, category ?? defaults.category, 'Categoría'),
    reliability: oneOf(RELIABILITY, reliability ?? defaults.reliability, 'Fiabilidad'),
    provenance: oneOf(PROVENANCE, provenance ?? defaults.provenance, 'Procedencia'),
    polarity: oneOf(POLARITY, polarity ?? 'risk', 'Polaridad'),
    techniques,
    // Marca suplantada, si la hay: permite correlacionar remitente y enlaces de la misma marca.
    brand: brand ?? null,
  };
}
