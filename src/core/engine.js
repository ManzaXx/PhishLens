// Motor de análisis: ejecuta los detectores, suma la puntuación y arma el informe.
import { parseEml, emailFromUrl } from '../parser/eml.js';
import { parseUrl } from '../parser/url.js';
import { finding, SEVERITY_ORDER } from './finding.js';
import { scoreFindings } from './scoring.js';
import { confidenceFor } from './confidence.js';
import { verdictFor } from './verdict.js';
import { extractIocs } from '../intel/ioc.js';
import { parseReceived } from '../parser/received.js';
import { authReport } from '../auth/index.js';
import { verifyDkimSignature } from '../auth/dkim.js';
import * as auth from '../detectors/auth.js';
import * as sender from '../detectors/sender.js';
import * as links from '../detectors/links.js';
import * as lookalike from '../detectors/lookalike.js';
import * as attachments from '../detectors/attachments.js';
import * as language from '../detectors/language.js';
import * as headers from '../detectors/headers.js';
import * as route from '../detectors/route.js';
import * as html from '../detectors/html.js';
import * as mime from '../detectors/mime.js';

export const DEFAULT_DETECTORS = [auth, sender, headers, route, mime, links, lookalike, attachments, html, language];

export { LEVELS, levelFor } from './scoring.js';

// Para el resumen se priorizan las señales más fáciles de entender.
const SUMMARY_PRIORITY = ['sender', 'links', 'attachments', 'html', 'lookalike', 'language', 'auth', 'route', 'headers', 'mime', 'input'];

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
  if (level === 'critical') return `Combina varias señales graves, entre ellas ${top}. No pulses enlaces ni abras adjuntos y bórralo.`;
  return level === 'phishing'
    ? `${strong.length === 1 ? `Una señal grave o media: ${top}` : `${strong.length} señales graves o medias, entre ellas ${top}`}. No pulses enlaces ni abras adjuntos.`
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

  const scored = scoreFindings(found);
  const { score, level, label } = scored;
  const risky = found.filter((f) => f.polarity !== 'trust' && f.severity !== 'info');
  const techniques = [...new Map(risky.flatMap((f) => f.techniques).map((t) => [t.id, t])).values()];
  const auth = authReport(email);
  const confidence = confidenceFor({
    hasHeaders: email.hasHeaders, auth, parseNotes: email.parseNotes ?? [], errors, categories: scored.categories,
  });
  const report = {
    score,
    level,
    label,
    summary: summarize(level, found),
    mainReason: scored.mainReason,
    categories: scored.categories,
    confidence,
    correlations: scored.correlations,
    trust: scored.trust,
    findings: found,
    techniques,
    errors,
    email: {
      from: email.from,
      replyTo: email.replyTo,
      returnPath: email.returnPath,
      subject: email.subject,
      links: email.links,
      attachments: email.attachments.map(({ bytes, ...meta }) => meta),
      authResults: email.headers?.get?.('authentication-results')?.[0] ?? null,
      date: email.headers?.get?.('date')?.[0] ?? null,
      route: email.hasHeaders ? parseReceived(email) : [],
      text: email.text,
      html: email.html,
    },
    auth,
    iocs: extractIocs(email),
  };
  report.verdict = verdictFor(report);
  return report;
}

/**
 * Punto de entrada de la UI: {kind: 'eml' | 'text' | 'url', value}.
 * Opcionales del analista: spfRecord (registro TXT pegado) y dkim (resultado de verifyDkimSignature).
 */
export function analyzeInput({ kind, value, spfRecord, dkim }) {
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
  if (spfRecord || dkim) email.analyst = { spfRecord: spfRecord || null, dkim: dkim ?? null };
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

/**
 * Verifica en local la primera firma DKIM del correo con la clave TXT que pega el analista.
 * El resultado se pasa luego a analyzeInput({ …, dkim }) para que el informe lo refleje.
 */
export function verifyDkimForInput({ kind, value }, keyTxt) {
  if (kind === 'url') return Promise.resolve({ ok: false, reason: 'no hay firma DKIM', domain: null, selector: null });
  return verifyDkimSignature(parseEml(value), keyTxt);
}
