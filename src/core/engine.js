// Motor de análisis: ejecuta los detectores, suma la puntuación y arma el informe.
import { parseEml, emailFromUrl } from '../parser/eml.js';
import { parseUrl } from '../parser/url.js';
import { finding, SEVERITY_ORDER } from './finding.js';
import { extractIocs } from '../intel/ioc.js';
import { parseReceived } from '../parser/received.js';
import * as auth from '../detectors/auth.js';
import * as sender from '../detectors/sender.js';
import * as links from '../detectors/links.js';
import * as lookalike from '../detectors/lookalike.js';
import * as attachments from '../detectors/attachments.js';
import * as language from '../detectors/language.js';
import * as headers from '../detectors/headers.js';
import * as html from '../detectors/html.js';

export const DEFAULT_DETECTORS = [auth, sender, headers, links, lookalike, attachments, html, language];

export const LEVELS = [
  { min: 60, level: 'phishing', label: 'Probable phishing' },
  { min: 25, level: 'suspicious', label: 'Sospechoso' },
  { min: 0, level: 'safe', label: 'Probablemente legítimo' },
];

export function levelFor(score) {
  const { level, label } = LEVELS.find((l) => score >= l.min);
  return { level, label };
}

// Para el resumen se priorizan las señales más fáciles de entender.
const SUMMARY_PRIORITY = ['sender', 'links', 'attachments', 'html', 'lookalike', 'language', 'auth', 'headers', 'input'];

function summarize(level, findings) {
  if (level === 'safe') {
    return findings.some((f) => f.points > 0)
      ? 'No hay señales fuertes de phishing, aunque conviene revisar los avisos de abajo.'
      : 'No se han encontrado señales de phishing.';
  }
  const strong = findings.filter((f) => f.severity === 'high' || f.severity === 'medium');
  const top = [...strong]
    .sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'high' ? -1 : 1)
      || SUMMARY_PRIORITY.indexOf(a.detector) - SUMMARY_PRIORITY.indexOf(b.detector))
    .slice(0, 2)
    .map((f) => `«${f.title}»`)
    .join(' y ');
  return level === 'phishing'
    ? `${strong.length} señales graves o medias, entre ellas ${top}. No pulses enlaces ni abras adjuntos.`
    : `${strong.length === 1 ? 'Una señal sospechosa' : `${strong.length} señales sospechosas`}: ${top}. Compruébalo por otra vía antes de actuar.`;
}

/** Analiza un email ya parseado. */
export function analyze(email, detectors = DEFAULT_DETECTORS, extra = []) {
  const found = [...extra];
  const errors = [];
  for (const detector of detectors) {
    try {
      found.push(...detector.detect(email));
    } catch (err) {
      errors.push({ detector: detector.name, message: err?.message ?? String(err) });
    }
  }
  found.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  const score = Math.min(100, found.reduce((sum, f) => sum + f.points, 0));
  const techniques = [...new Map(found.filter((f) => f.mitre && f.points > 0).map((f) => [f.mitre.id, f.mitre])).values()];
  const { level, label } = levelFor(score);
  return {
    score,
    level,
    label,
    summary: summarize(level, found),
    findings: found,
    techniques,
    errors,
    email: {
      from: email.from,
      replyTo: email.replyTo,
      returnPath: email.returnPath,
      subject: email.subject,
      links: email.links,
      attachments: email.attachments,
      authResults: email.headers?.get?.('authentication-results')?.[0] ?? null,
      date: email.headers?.get?.('date')?.[0] ?? null,
      route: email.hasHeaders ? parseReceived(email) : [],
      text: email.text,
      html: email.html,
    },
    iocs: extractIocs(email),
  };
}

/** Punto de entrada de la UI: {kind: 'eml' | 'text' | 'url', value}. */
export function analyzeInput({ kind, value }) {
  if (kind === 'url') {
    const extra = [];
    if (!parseUrl(value)) {
      extra.push(finding({
        id: 'input.invalid-url',
        detector: 'input',
        severity: 'info',
        title: 'No parece una URL válida',
        detail: 'Escribe una dirección que empiece por http://, https:// o www.',
        evidence: String(value ?? '').slice(0, 200),
      }));
    }
    return analyze(emailFromUrl(value), DEFAULT_DETECTORS, extra);
  }

  const email = parseEml(value);
  const extra = [];
  if (!email.hasHeaders) {
    extra.push(finding({
      id: 'input.no-headers',
      detector: 'input',
      severity: 'info',
      title: 'Sin cabeceras',
      detail: 'Solo se ha analizado el texto. Para un análisis completo pega el email original con sus cabeceras (en Gmail: ⋮ → "Mostrar original").',
    }));
  }
  return analyze(email, DEFAULT_DETECTORS, extra);
}
