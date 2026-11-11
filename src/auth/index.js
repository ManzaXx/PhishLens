// Autenticación en estados (spec 2.2, §4): qué se ha comprobado de verdad, qué solo se ha leído
// en una cabecera (y si esa cabecera es de fiar) y qué no se puede saber sin red.
//
// state ∈ 'verified' | 'declared-trusted' | 'declared-untrusted' | 'unverifiable' | 'absent'
import { classifyAuthResults } from './trust.js';
import { dmarcAlignment } from './dmarc.js';
import { checkDkimBodies } from './dkim.js';
import { originIp, evaluateSpfRecord } from './spf.js';

const memo = new WeakMap();
const DEFINITIVE_SPF = new Set(['pass', 'fail', 'softfail', 'neutral', 'permerror']);
const KEY_PROBLEMS = new Set(['clave revocada', 'clave mal formada', 'algoritmo no compatible', 'firma mal formada', 'no hay firma DKIM']);

const domainOf = (value) => {
  const text = String(value ?? '').trim().toLowerCase();
  const at = text.lastIndexOf('@');
  return (at >= 0 ? text.slice(at + 1) : text) || null;
};

/** Elige la cabecera que se lee: la de confianza; si no hay, la primera que no sea falsa. */
function pickHeader(headers) {
  return headers.find((h) => h.trusted) ?? headers.find((h) => !h.forged) ?? null;
}

function declared(header, method) {
  if (!header) return null;
  const r = header.parsed.results.find((x) => x.method === method);
  if (!r) return null;
  return {
    state: header.trusted ? 'declared-trusted' : 'declared-untrusted',
    result: r.result,
    detail: header.why,
    detailRef: header.whyRef,
    source: header.parsed.authservId || null,
    props: r.props,
  };
}

const absent = (detail, code) => ({ state: 'absent', result: null, detail, detailRef: { code, params: {} }, source: null });

function evaluateSpf(email, header) {
  const fromHeader = declared(header, 'spf');
  const record = email.analyst?.spfRecord;
  if (record) {
    const ip = originIp(email);
    if (!ip) {
      return { ...(fromHeader ?? absent('', 'report.auth.spf.no-ip')), detail: 'Registro SPF pegado, pero no se encuentra la IP de origen en los Received.', detailRef: { code: 'report.auth.spf.no-ip', params: {} }, offline: null };
    }
    const offline = { ip, ...evaluateSpfRecord(record, ip) };
    if (DEFINITIVE_SPF.has(offline.result)) {
      const detail = `PhishLens evaluó el registro pegado contra ${ip}${offline.mechanism ? ` (${offline.mechanism})` : ''}.`;
      // La identidad SPF verificada es la del sobre (Return-Path), nunca la que diga una cabecera.
      const props = { 'smtp.mailfrom': email.returnPath ?? '' };
      const detailRef = { code: 'report.auth.spf.verified', params: { ip, mechanism: offline.mechanism ? ` (${offline.mechanism})` : '' } };
      return { state: 'verified', result: offline.result, detail, detailRef, source: 'PhishLens', offline, props };
    }
    const need = `Para decidir hace falta consultar DNS: ${offline.needs.join(', ')}.`;
    const needs = offline.needs.join(', ');
    if (fromHeader) return { ...fromHeader, detail: `${fromHeader.detail}. ${need}`, detailRef: { code: 'report.auth.spf.declared-need', params: { why: fromHeader.detailRef, needs } }, offline };
    return { state: 'unverifiable', result: null, detail: need, detailRef: { code: 'report.auth.spf.need', params: { needs } }, source: null, offline };
  }
  return fromHeader ?? absent('Ninguna cabecera informa de SPF.', 'report.auth.spf.absent');
}

function evaluateDkim(email, header, bodies) {
  const local = email.analyst?.dkim;
  if (local && !KEY_PROBLEMS.has(local.reason)) {
    return {
      state: 'verified', result: local.ok ? 'pass' : 'fail',
      detail: `PhishLens comprobó la firma de ${local.domain} (selector ${local.selector}): ${local.reason}.`,
      // El motivo de bajo nivel (local.reason) es un texto técnico corto que no se traduce (docs/limitations.md).
      detailRef: { code: 'report.auth.dkim.verified', params: { domain: local.domain, selector: local.selector, reason: local.reason } },
      source: 'PhishLens', domain: local.domain,
    };
  }
  const fromHeader = declared(header, 'dkim');
  if (fromHeader) return fromHeader;
  if (bodies.length > 0) {
    const why = local ? `No se pudo comprobar: ${local.reason}.` : 'Hay firma DKIM, pero comprobarla requiere la clave pública del dominio.';
    const detailRef = local ? { code: 'report.auth.dkim.unverifiable-local', params: { reason: local.reason } } : { code: 'report.auth.dkim.unverifiable', params: {} };
    return { state: 'unverifiable', result: null, detail: why, detailRef, source: null };
  }
  return absent('El correo no lleva firma DKIM.', 'report.auth.dkim.absent');
}

function evaluateDmarc(email, header, spf, dkim) {
  const fromDomain = email.from?.domain ?? null;
  const spfDomain = domainOf(spf.props?.['smtp.mailfrom'] ?? spf.props?.['smtp.helo']);
  const dkimDomain = dkim.domain ?? domainOf(dkim.props?.['header.d'] ?? dkim.props?.['header.i']);
  const alignment = dmarcAlignment({
    fromDomain,
    spf: spf.result ? { result: spf.result, domain: spfDomain } : null,
    dkim: dkim.result ? [{ result: dkim.result, domain: dkimDomain }] : [],
  });
  // Un pass sin dominio podría estar alineado: no se puede afirmar que no lo esté.
  const unknownPass = (spf.result === 'pass' && !spfDomain) || (dkim.result === 'pass' && !dkimDomain);
  const hasResults = Boolean(spf.result || dkim.result);
  const judgeable = hasResults && Boolean(fromDomain) && !unknownPass;

  const verifiedPass = (spf.state === 'verified' && alignment.spfAligned) || (dkim.state === 'verified' && alignment.dkimAligned);
  const fromHeader = declared(header, 'dmarc');
  let result;
  if (verifiedPass) {
    result = { state: 'verified', result: 'pass', detail: `PhishLens comprobó un ${alignment.via.toUpperCase()} alineado con ${fromDomain} (política del dominio desconocida sin DNS).`, detailRef: { code: 'report.auth.dmarc.verified', params: { via: alignment.via.toUpperCase(), domain: fromDomain } }, source: 'PhishLens' };
  } else {
    result = fromHeader ?? absent('Ninguna cabecera informa de DMARC.', 'report.auth.dmarc.absent');
  }
  return { ...result, alignment: { ...alignment, judgeable, fromDomain } };
}

const strip = ({ props, offline, ...rest }) => rest;

/** Evalúa SPF, DKIM y DMARC del correo. Memoizada por objeto email. */
export function evaluateAuth(email) {
  const cached = memo.get(email);
  if (cached) return cached;
  const classified = classifyAuthResults(email);
  const header = pickHeader(classified.headers);
  const bodies = checkDkimBodies(email);
  const spf = evaluateSpf(email, header);
  const dkim = evaluateDkim(email, header, bodies);
  const dmarc = evaluateDmarc(email, header, spf, dkim);
  const result = {
    spf: strip(spf),
    dkim: strip(dkim),
    dmarc: strip(dmarc),
    headers: classified.headers.map(({ index, parsed, trusted, forged, why, whyRef }) => ({
      index, authservId: parsed.authservId, trusted, forged, why, whyRef, results: parsed.results.map(({ method, result: r }) => ({ method, result: r })),
    })),
    // Datos internos para el detector (no van al informe).
    internal: { header, classified, bodies, spfOffline: spf.offline ?? null },
  };
  memo.set(email, result);
  return result;
}

/** Copia del resultado apta para el informe: sin cabeceras en bruto ni datos internos. */
export function authReport(email) {
  const { internal, ...rest } = evaluateAuth(email);
  return rest;
}
