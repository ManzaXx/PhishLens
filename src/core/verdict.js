// Veredicto en lenguaje llano para el modo sencillo (spec 2.3, §3).
import { adviceFor } from './advice.js';
import { weight } from './scoring.js';

const TONES = new Map([['safe', 'safe'], ['suspicious', 'suspicious'], ['phishing', 'phishing'], ['critical', 'phishing']]);
const HEADLINES = new Map([['safe', 'Parece legítimo'], ['suspicious', 'Ten cuidado'], ['phishing', 'No te fíes: es phishing']]);
const NOTHING = 'No hemos encontrado nada que indique un engaño.';
// Pasos de relleno cuando adviceFor da menos de tres: siempre útiles y nunca alarmistas.
const EXTRA_STEPS = [
  'Si te piden datos o dinero, compruébalo por otra vía: la web o el teléfono oficial.',
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

function because(report, top) {
  const brand = report.findings.filter(isBrandSender).sort(byWeight)[0];
  const domain = domainOf(report.email?.from?.address);
  if (brand && domain) return `Dice ser de ${brand.brand}, pero lo envía ${domain}, un dominio que no es suyo.`;
  if (top.length) return top[0].plain || top[0].title;
  return NOTHING;
}

function steps(report) {
  const out = [...adviceFor(report)].slice(0, 3);
  for (const s of EXTRA_STEPS) if (out.length < 3 && !out.includes(s)) out.push(s);
  return out;
}

/** {tone, headline, because, steps, top} a partir del informe del motor. */
export function verdictFor(report) {
  const tone = TONES.get(report.level) ?? 'suspicious';
  // Una señal por texto: dos dominios parecidos de la misma marca se leerían igual dos veces.
  const seen = new Set();
  const top = report.findings.filter(isRisk).sort(byWeight)
    .filter((f) => { const k = f.plain || f.title; return seen.has(k) ? false : seen.add(k); })
    .slice(0, 5);
  return { tone, headline: HEADLINES.get(tone), because: because(report, top), steps: steps(report), top };
}
