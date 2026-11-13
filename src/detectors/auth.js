// Detector de autenticación del remitente: SPF, DKIM y DMARC, distinguiendo lo que PhishLens
// comprueba, lo que una cabecera declara (y si es de fiar) y lo que no se puede saber sin red.
import { finding } from '../core/finding.js';
import { own } from '../lib/text.js';
import { evaluateAuth } from '../auth/index.js';

export const name = 'auth';

const CHECKS = [
  {
    key: 'spf',
    label: 'SPF',
    detail: 'SPF comprueba que el servidor que envió el email está autorizado por el dominio. Si falla, el remitente puede estar falsificado.',
  },
  {
    key: 'dkim',
    label: 'DKIM',
    detail: 'DKIM es una firma digital del dominio. Si falla, el mensaje pudo ser modificado o no lo firmó quien dice ser.',
  },
  {
    key: 'dmarc',
    label: 'DMARC',
    detail: 'DMARC es la política del dominio sobre qué hacer si SPF y DKIM fallan. Un fallo de DMARC es una señal fuerte de suplantación.',
  },
];

const SEVERITY = { fail: 'high', permerror: 'medium', softfail: 'medium', temperror: 'low', none: 'low', neutral: 'low' };
const UNTRUSTED_NOTE = ' Ojo: esta cabecera no la añadió el servidor que recibió el correo, así que podría estar inventada.';
const WEAK = { 'l-tag': 'la firma solo cubre parte del cuerpo (l=)', expired: 'la firma ha caducado (x=)', 'rsa-sha1': 'usa RSA-SHA1, prohibido por RFC 8301' };
const clip = (text, max = 300) => (text.length > max ? `${text.slice(0, max)}…` : text);

function declaredFindings(header) {
  const out = [];
  for (const check of CHECKS) {
    const r = header.parsed.results.find((x) => x.method === check.key);
    if (!r) continue;
    const severity = own(SEVERITY, r.result);
    if (!severity) continue;
    out.push(finding({
      id: `auth.${check.key}`,
      detector: name,
      severity,
      title: `${check.label}: ${r.result}`,
      params: { result: r.result, authserv: header.parsed.authservId || null, ...(header.trusted ? {} : { variant: 'untrusted' }) },
      detail: header.trusted ? check.detail : check.detail + UNTRUSTED_NOTE,
      evidence: `${check.key}=${r.result}${header.parsed.authservId ? ` (según ${header.parsed.authservId})` : ''}`,
      reliability: header.trusted ? 'medium' : 'low',
    }));
  }
  return out;
}

function forgedFindings(headers) {
  return headers.filter((h) => h.forged).map((h) => finding({
    id: 'auth.forged-results',
    detector: name,
    severity: 'high',
    title: 'Resultados de autenticación falsificados',
    params: { why: h.whyRef },
    detail: `Hay una cabecera Authentication-Results que ${h.why}. Quien envía el correo la escribió para aparentar que pasó SPF, DKIM o DMARC.`,
    evidence: clip(h.raw),
    reliability: 'high',
    provenance: 'inferred',
  }));
}

function dmarcFindings(auth) {
  const { alignment } = auth.dmarc;
  const { header, classified } = auth.internal;
  if (!alignment.judgeable || alignment.aligned) return [];
  const evidence = `From: ${alignment.fromDomain}`;
  if (header?.trusted && auth.dmarc.result === 'pass') {
    return [finding({
      id: 'auth.dmarc-declared-mismatch',
      detector: name,
      severity: 'high',
      title: 'DMARC declarado como pass sin ningún resultado alineado',
      params: { authserv: header.parsed.authservId },
      detail: `La cabecera de ${header.parsed.authservId} dice dmarc=pass, pero ni SPF ni DKIM pasan con un dominio que coincida con el remitente visible. Las piezas no cuadran.`,
      evidence,
      reliability: 'high',
      provenance: 'inferred',
    })];
  }
  const declaresFail = classified.headers.some((h) => h.parsed.results.some((r) => r.method === 'dmarc' && r.result === 'fail'));
  if (declaresFail) return [];
  return [finding({
    id: 'auth.dmarc-unaligned',
    detector: name,
    severity: 'medium',
    title: 'Ni SPF ni DKIM respaldan al remitente visible',
    params: {},
    detail: 'DMARC exige que SPF o DKIM pasen con el mismo dominio (organizativo) que aparece en el From. Aquí no ocurre, así que el remitente que ves no está autenticado.',
    evidence,
    reliability: 'medium',
    provenance: 'inferred',
  })];
}

function dkimFindings(bodies) {
  const out = [];
  const domains = (list) => [...new Set(list.map((b) => `d=${b.sig.d}`))].join(', ');
  const modified = bodies.filter((b) => b.bodyHashOk === false);
  const verified = bodies.filter((b) => b.bodyHashOk === true);
  if (modified.length) {
    out.push(finding({
      id: 'auth.dkim-body-modified',
      detector: name,
      severity: 'high',
      title: 'El cuerpo no coincide con la firma DKIM',
      params: {},
      detail: 'PhishLens ha calculado el hash del cuerpo y no coincide con el que firmó el dominio (bh=). El contenido se modificó después de firmarse.',
      evidence: domains(modified),
      reliability: 'high',
      provenance: 'verified',
    }));
  }
  if (verified.length) {
    out.push(finding({
      id: 'auth.dkim-body-verified',
      detector: name,
      severity: 'info',
      title: 'El cuerpo coincide con la firma DKIM',
      params: {},
      detail: 'PhishLens ha comprobado que el cuerpo es el mismo que firmó el dominio. La firma en sí solo se puede verificar con su clave pública.',
      evidence: domains(verified),
      reliability: 'high',
      provenance: 'verified',
    }));
  }
  const weak = bodies.filter((b) => b.issues.some((i) => own(WEAK, i)));
  if (weak.length) {
    const reasons = [...new Set(weak.flatMap((b) => b.issues.map((i) => own(WEAK, i)).filter(Boolean)))];
    out.push(finding({
      id: 'auth.dkim-weak',
      detector: name,
      severity: 'low',
      title: 'Firma DKIM débil',
      params: { reasons: [...new Set(weak.flatMap((b) => b.issues.filter((i) => own(WEAK, i))))].map((i) => ({ key: `rule.auth.dkim-weak.${i}` })) },
      detail: `La firma existe pero ofrece menos garantías: ${reasons.join('; ')}.`,
      evidence: domains(weak),
      reliability: 'medium',
      provenance: 'verified',
    }));
  }
  return out;
}

function spfOfflineFindings(offline) {
  if (!offline || (offline.result !== 'fail' && offline.result !== 'softfail')) return [];
  return [finding({
    id: 'auth.spf-offline',
    detector: name,
    severity: offline.result === 'fail' ? 'high' : 'medium',
    title: `SPF comprobado en local: ${offline.result}`,
    params: { result: offline.result, ip: offline.ip },
    detail: `Según el registro SPF que has pegado, la IP ${offline.ip} no está autorizada a enviar correo de ese dominio.`,
    evidence: `${offline.ip} → ${offline.mechanism ?? 'sin coincidencia'}`,
    reliability: 'high',
    provenance: 'verified',
  })];
}

// Señal a favor solo si PhishLens verificó la firma con la clave y está alineada con el From:
// un bh= que cuadra lo puede fabricar cualquiera calculando el hash de su propio cuerpo.
function trustFindings(auth) {
  if (auth.dkim.state !== 'verified' || auth.dkim.result !== 'pass' || !auth.dmarc.alignment?.dkimAligned) return [];
  return [finding({
    id: 'auth.dkim-verified-aligned',
    detector: name,
    severity: 'info',
    title: 'Firma DKIM verificada y alineada con el remitente',
    params: { domain: auth.dkim.domain ?? { key: 'rule.auth.its-domain' } },
    detail: `PhishLens comprobó la firma con la clave pública de ${auth.dkim.domain ?? 'su dominio'}, y ese dominio coincide con el del From.`,
    evidence: auth.dkim.detail ?? '',
    reliability: 'high',
    provenance: 'verified',
    polarity: 'trust',
  })];
}

export function detect(email) {
  if (!email.hasHeaders) return [];
  const auth = evaluateAuth(email);
  const { header, classified, bodies, spfOffline } = auth.internal;
  const out = [...forgedFindings(classified.headers)];
  if (classified.headers.length === 0) {
    // Informativo (auditoría 3.1, P7): un .eml exportado de «Enviados» o reenviado como adjunto no trae esta
    // cabecera y es legítimo. No suma; sí baja la confianza del análisis (confidence.js, autenticación ausente).
    out.push(finding({
      id: 'auth.missing',
      detector: name,
      severity: 'info',
      title: 'Sin resultados de autenticación',
      params: {},
      detail: 'El email no incluye la cabecera Authentication-Results, así que no se puede verificar SPF, DKIM ni DMARC.',
      evidence: 'Falta la cabecera Authentication-Results',
    }));
  }
  if (header) out.push(...declaredFindings(header));
  out.push(...dmarcFindings(auth), ...dkimFindings(bodies), ...spfOfflineFindings(spfOffline), ...trustFindings(auth));
  return out;
}
