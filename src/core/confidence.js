// Confianza del análisis (spec 2.2, §7.3): cuánto nos podemos fiar del informe, no cuánto
// riesgo hay. Solo mira carencias de la entrada y del análisis, nunca la nota.

const DEDUCTIONS = [
  { amount: 0.4, code: 'report.confidence.no-headers', reason: 'Sin cabeceras: solo se ha analizado el texto.', applies: (x) => !x.hasHeaders },
  {
    amount: 0.2,
    code: 'report.confidence.auth-unconfirmed', reason: 'La autenticación no se puede confirmar: no hay resultados de confianza.',
    applies: (x) => states(x).every((s) => WEAK_STATES.has(s)),
  },
  { amount: 0.1, code: 'report.confidence.nothing-verified', reason: 'PhishLens no ha verificado nada por sí mismo.', applies: (x) => !states(x).includes('verified') },
  { amount: 0.15, code: 'report.confidence.partial-read', reason: 'El correo no se pudo leer entero (límites o MIME roto).', applies: (x) => (x.parseNotes?.length ?? 0) > 0 },
  {
    amount: 0.6,
    code: 'report.confidence.hidden-parts', reason: 'Parte del correo no se ha leído (más de 1.000 cabeceras o más de 25 MB): el veredicto puede estar incompleto.',
    applies: (x) => (x.parseNotes ?? []).some((n) => HIDING_LIMITS.has(n.code)),
  },
  { amount: 0.15, code: 'report.confidence.detector-failed', reason: 'Algún detector falló.', applies: (x) => (x.errors?.length ?? 0) > 0 },
  { amount: 0.1, code: 'report.confidence.one-category', reason: 'Solo una categoría aporta riesgo.', applies: (x) => (x.categories ?? []).filter((c) => c.score > 0).length === 1 },
];

// Límites que dejan sin leer parte de la estructura del correo.
const HIDING_LIMITS = new Set(['limit.headers', 'limit.input-bytes']);
const WEAK_STATES = new Set(['declared-untrusted', 'unverifiable', 'absent']);
const states = (x) => ['spf', 'dkim', 'dmarc'].map((k) => x.auth?.[k]?.state ?? 'absent');

/**
 * @param {{hasHeaders: boolean, auth: object, parseNotes: Array, errors: Array, categories: Array}} input
 * @returns {{level: 'high'|'medium'|'low', value: number, reasons: string[], codes: string[]}} (codes: report.confidence.*, en paralelo a reasons)
 */
export function confidenceFor(input) {
  const hits = DEDUCTIONS.filter((d) => d.applies(input));
  // Se trabaja en centésimas para que 1 − 0,15 − 0,10 dé 0,75 exacto.
  const cents = Math.max(0, 100 - hits.reduce((sum, d) => sum + Math.round(d.amount * 100), 0));
  const value = cents / 100;
  const level = value >= 0.75 ? 'high' : value >= 0.45 ? 'medium' : 'low';
  return { level, value, reasons: hits.map((d) => d.reason), codes: hits.map((d) => d.code) };
}
