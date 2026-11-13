// Nota de riesgo contextual (spec 2.2, §7.2). Funciones puras: mismo conjunto de hallazgos,
// misma nota, en cualquier orden. Explicación completa en docs/scoring.md.

export const CATEGORY_MAX = Object.freeze({
  authentication: 25, sender: 20, links: 20, attachments: 15, language: 10, infrastructure: 10,
});

export const CATEGORY_LABELS = Object.freeze({
  authentication: 'Autenticación',
  sender: 'Remitente y suplantación',
  links: 'Enlaces y contenido',
  attachments: 'Adjuntos',
  language: 'Lenguaje',
  infrastructure: 'Infraestructura',
});

/**
 * Escala del OR ruidoso entre categorías. Con la suma simple, 8 enlaces sospechosos se quedan
 * en «legítimo» y suplantación + .exe + DMARC fallido no llega a «crítico» (los ejemplos de §7.4).
 */
export const SCALE = 40;

const BASE = Object.freeze({ info: 0, low: 0.25, medium: 0.5, high: 0.9 });
const FACTOR = Object.freeze({ high: 1, medium: 0.75, low: 0.5 });
const CORRELATION_SHARE = 0.25;
const MAX_CORRELATIONS = 2;
// Una firma verificada hace menos creíbles las señales blandas, nunca las de suplantación.
const SOFTENED = new Set(['language', 'infrastructure']);

export const LEVELS = Object.freeze([
  { min: 80, level: 'critical', label: 'Phishing casi seguro' },
  { min: 60, level: 'phishing', label: 'Probable phishing' },
  { min: 25, level: 'suspicious', label: 'Sospechoso' },
  { min: 0, level: 'safe', label: 'Probablemente legítimo' },
]);

export function levelFor(score) {
  const { level, label } = LEVELS.find((l) => score >= l.min);
  return { level, label };
}

/** Peso de un hallazgo de riesgo entre 0 y 0,9. */
export function weight(f) {
  return (BASE[f.severity] ?? 0) * (FACTOR[f.reliability] ?? FACTOR.low);
}

const isRisk = (f) => f.polarity !== 'trust' && f.severity !== 'info';

// OR ruidoso: 1 − Π(1 − pᵢ). Se ordena antes de multiplicar para que el resultado no dependa
// del orden ni siquiera en el último decimal de coma flotante.
const noisyOr = (ps) => 1 - [...ps].sort((a, b) => a - b).reduce((acc, p) => acc * (1 - p), 1);

const IMPERSONATION = /^sender\.(brand-impersonation|display-name-address|mixed-script)$/;
const isImpersonation = (f) => IMPERSONATION.test(f.id) || (f.id.startsWith('lookalike.') && f.category === 'sender');
const lookalikeLink = (f) => f.id.startsWith('lookalike.') && f.category === 'links';
// Una marca nombrada en la ruta de un enlace solo cuenta si el enlace ya es raro (IP o login sin HTTPS):
// medium.com/paypal-tech no suplanta a nadie.
function brandSignals(risk) {
  const odd = risk.some((f) => f.id === 'links.ip' || f.id === 'links.insecure-login');
  return risk.filter((f) => isImpersonation(f) || lookalikeLink(f) || (odd && f.id === 'links.brand-in-path'));
}
// Un hecho, una señal (auditoría 3.1, P6): «el From dice ser la marca X y su dominio no es de X» lo cuentan a la vez
// sender.brand-impersonation y el lookalike del From. Dentro de la categoría Remitente, las señales de suplantación
// de la misma marca se funden en una y cuenta la de más peso. Las de distinta marca, o en Enlaces, siguen aparte.
const sameFactKey = (f) => (f.category === 'sender' && isImpersonation(f) && f.brand ? `brand:${f.brand}` : null);
function categoryWeights(list) {
  const merged = new Map();
  const out = [];
  for (const f of list) {
    const key = sameFactKey(f);
    if (!key) { out.push(weight(f)); continue; }
    merged.set(key, Math.max(merged.get(key) ?? 0, weight(f)));
  }
  return [...out, ...merged.values()];
}
// Fallos reales de autenticación: no tener cabecera o una firma débil no es «fallida».
const authFailure = (f) => f.id.startsWith('auth.') && (f.severity === 'medium' || f.severity === 'high') && f.id !== 'auth.dkim-weak';
const CREDENTIALS = ['html.form', 'language.credentials', 'links.insecure-login'];

const CORRELATIONS = [
  {
    id: 'brand-auth',
    label: 'Suplantación de marca con autenticación fallida',
    match: (risk) => [risk.filter(isImpersonation), risk.filter(authFailure)],
  },
  {
    id: 'brand-credentials',
    label: 'Suplantación de marca que pide credenciales',
    match: (risk) => [brandSignals(risk), risk.filter((f) => CREDENTIALS.includes(f.id))],
  },
  {
    id: 'brand-raw-ip',
    label: 'Marca suplantada con enlaces a una dirección IP',
    match: (risk) => [brandSignals(risk), risk.filter((f) => f.id === 'links.ip')],
  },
  {
    id: 'credentials-link',
    label: 'Pide credenciales y da un enlace sospechoso para ello',
    match: (risk) => [
      risk.filter((f) => f.id === 'language.credentials' || f.id === 'html.form'),
      risk.filter((f) => f.id.startsWith('links.') && f.id !== 'links.insecure-login' && f.id !== 'links.brand-in-path'),
    ],
  },
  {
    id: 'attachment-pressure',
    label: 'Adjunto peligroso con presión para abrirlo',
    match: (risk) => [
      risk.filter((f) => /^attachments\.(dangerous|double-extension|rtl-override|macro|ole-macro|lnk|disk-image|archive-executable|type-mismatch|html-smuggling|pdf-active)$/.test(f.id)),
      risk.filter((f) => /^language\.(urgency|threat)$/.test(f.id)),
    ],
  },
  {
    id: 'lookalike-same-brand',
    label: 'Enlace que imita a la misma marca que el remitente',
    match: (risk) => {
      const brands = new Set(risk.filter(isImpersonation).map((f) => f.brand).filter(Boolean));
      const links = risk.filter((f) => f.id.startsWith('lookalike.') && f.category === 'links' && brands.has(f.brand));
      return [risk.filter((f) => isImpersonation(f) && links.some((l) => l.brand === f.brand)), links];
    },
  },
];

const ids = (list) => [...new Set(list.map((f) => f.id))].sort();

// [texto, referencia]: la referencia usa ids de correlación y de categoría, nunca frases.
function mainReasonFor(score, correlations, categories) {
  if (correlations.length) {
    return [`Motivo principal: ${correlations[0].label}.`, { code: 'report.main.correlation', params: { correlation: { key: `correlation.${correlations[0].id}` } } }];
  }
  if (score === 0) return ['No se han encontrado señales de riesgo.', { code: 'report.main.none', params: {} }];
  const top = categories.filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score || Object.keys(CATEGORY_MAX).indexOf(a.id) - Object.keys(CATEGORY_MAX).indexOf(b.id))
    .slice(0, 2);
  const [a, b] = top.map((c) => ({ key: `category.${c.id}` }));
  return [`Pesa sobre todo: ${top.map((c) => c.label).join(' y ')}.`, { code: b ? 'report.main.top.two' : 'report.main.top.one', params: b ? { a, b } : { a } }];
}

/**
 * Calcula la nota contextual de un conjunto de hallazgos.
 * @returns {{score, baseScore, level, label, categories, correlations, trust, mainReason, mainReasonRef}}
 */
export function scoreFindings(findings) {
  const risk = findings.filter(isRisk);
  const verifiedTrust = findings.some((f) => f.polarity === 'trust' && f.provenance === 'verified');

  const exact = {};
  for (const [id, max] of Object.entries(CATEGORY_MAX)) {
    let value = max * noisyOr(categoryWeights(risk.filter((f) => f.category === id)));
    if (verifiedTrust && SOFTENED.has(id)) value *= 0.5;
    exact[id] = Math.min(max, value);
  }
  const baseExact = 100 * noisyOr(Object.values(exact).map((s) => s / SCALE));

  const correlations = [];
  for (const rule of CORRELATIONS) {
    const [left, right] = rule.match(risk);
    if (left.length && right.length) correlations.push({ id: rule.id, label: rule.label, findings: ids([...left, ...right]) });
  }
  let total = baseExact;
  for (const _ of correlations.slice(0, MAX_CORRELATIONS)) total += (100 - total) * CORRELATION_SHARE;

  const score = Math.max(0, Math.min(100, Math.round(total)));
  const categories = Object.entries(CATEGORY_MAX).map(([id, max]) => ({
    id, label: CATEGORY_LABELS[id], score: Math.min(max, Math.round(exact[id] * 10) / 10), max,
  }));
  return {
    score,
    baseScore: Math.round(baseExact * 10) / 10,
    ...levelFor(score),
    categories,
    correlations,
    trust: ids(findings.filter((f) => f.polarity === 'trust')),
    ...(([mainReason, mainReasonRef]) => ({ mainReason, mainReasonRef }))(mainReasonFor(score, correlations, categories)),
  };
}
