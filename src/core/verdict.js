// Veredicto en lenguaje llano para el modo sencillo (spec 2.3, §3).
import { adviceCodesFor, adviceText } from './advice.js';
import { weight } from './scoring.js';

const TONES = new Map([['safe', 'safe'], ['suspicious', 'suspicious'], ['phishing', 'phishing'], ['critical', 'phishing']]);
const HEADLINES = new Map([['safe', 'Parece legítimo'], ['suspicious', 'Ten cuidado'], ['phishing', 'No te fíes: es phishing']]);
const NOTHING = 'No hemos encontrado nada que indique un engaño.';
// Pasos de relleno cuando adviceFor da menos de tres: siempre útiles y nunca alarmistas.
const EXTRA_STEPS = [
  // report.verdict.extra.1 … 3
  'Mira bien a dónde lleva un enlace antes de pulsarlo: pasa el ratón o mantén el dedo encima.',
  'Ante la duda, no pulses los enlaces: escribe tú la dirección de la web.',
  'Si algo no te cuadra, pregunta a alguien de confianza antes de actuar.',
];

const isRisk = (f) => f.polarity !== 'trust' && f.points > 0;
const byWeight = (a, b) => weight(b) - weight(a) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const isBrandSender = (f) => f.brand && (f.id === 'sender.brand-impersonation' || (f.id.startsWith('lookalike.') && f.category === 'sender'));

function domainOf(address) {
  const at = String(address ?? '').lastIndexOf('@');
  return at === -1 ? '' : address.slice(at + 1).toLowerCase();
}

// [texto, referencia]: la referencia es la frase en códigos que la interfaz traduce.
function because(report, top) {
  const brand = report.findings.filter(isBrandSender).sort(byWeight)[0];
  const domain = domainOf(report.email?.from?.address);
  if (brand && domain) {
    return [`Dice ser de ${brand.brand}, pero lo envía ${domain}, un dominio que no es suyo.`, { code: 'report.verdict.brand', params: { brand: brand.brand, domain } }];
  }
  if (top.length) return [top[0].plain || top[0].title, { code: 'rule', id: top[0].id, at: report.findings.indexOf(top[0]) }];
  return [NOTHING, { code: 'report.verdict.nothing', params: {} }];
}

function stepCodes(report) {
  const codes = adviceCodesFor(report).slice(0, 3);
  EXTRA_STEPS.forEach((_, i) => { if (codes.length < 3) codes.push(`report.verdict.extra.${i + 1}`); });
  return codes;
}
const stepText = (code) => adviceText(code) ?? EXTRA_STEPS[Number(code.split('.').at(-1)) - 1];

/** {tone, headline, because, steps, top} y sus códigos (headlineCode, becauseRef, stepCodes) a partir del informe del motor. */
export function verdictFor(report) {
  const tone = TONES.get(report.level) ?? 'suspicious';
  // Una señal por texto: dos dominios parecidos de la misma marca se leerían igual dos veces.
  const seen = new Set();
  const top = report.findings.filter(isRisk).sort(byWeight)
    .filter((f) => { const k = f.plain || f.title; return seen.has(k) ? false : seen.add(k); })
    .slice(0, 5);
  const [text, becauseRef] = because(report, top);
  const codes = stepCodes(report);
  return {
    tone, headline: HEADLINES.get(tone), because: text, steps: codes.map(stepText), top,
    headlineCode: `report.verdict.${tone}`, becauseRef, stepCodes: codes,
  };
}
