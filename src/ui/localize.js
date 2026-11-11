// Informe en el idioma activo (spec 3.1, PR15). El núcleo escribe en español y deja al lado
// referencias neutras (id de regla y params, o code y params); aquí se traducen en un solo sitio.
// Función pura: devuelve una copia y nunca muta el informe. En español, la copia es igual al original.
import { getLang, tr, trProblem } from '../i18n/index.js';

const GENERIC_BRAND = { key: 'rule.brand.generic' };

const ruleKey = (f, part) => `rule.${f.id}.${part}`;
const plainParams = (f) => ({ ...(f.params ?? {}), brand: f.brand || GENERIC_BRAND });
const translatable = (f) => f && !f.custom && f.detector !== 'custom' && typeof f.id === 'string';

/** Textos de un hallazgo: [campo, clave, params]. Una regla sin texto llano usa su título también ahí. */
function findingParts(f) {
  const variant = typeof f.params?.variant === 'string' ? `.${f.params.variant}` : '';
  const parts = [['title', ruleKey(f, 'title'), f.params], ['detail', `${ruleKey(f, 'detail')}${variant}`, f.params]];
  if (f.plain !== f.title) parts.push(['plain', ruleKey(f, 'plain'), plainParams(f)]);
  return parts;
}

function localizeFinding(f) {
  if (!translatable(f)) return f;
  const out = { ...f };
  for (const [field, key, params] of findingParts(f)) out[field] = tr(key, params, f[field]);
  if (f.plain === f.title) out.plain = out.title;
  // Solo la evidencia que escribe el motor con palabras (spf=fail (según X)); el resto es dato tal cual.
  if (f.params?.authserv && f.evidence) out.evidence = tr(ruleKey(f, 'evidence'), f.params, f.evidence);
  return out;
}

const relabel = (prefix) => (item) => (item?.id ? { ...item, label: tr(`${prefix}.${item.id}`, {}, item.label) } : item);

// Una referencia {code, params} a su texto, o `fallback` si no hay referencia o no se puede usar.
const viaRef = (ref, fallback) => (ref?.code ? tr(ref.code, ref.params ?? {}, fallback) : fallback);
const refProblem = (ref) => (ref?.code ? trProblem(ref.code, ref.params ?? {}) : null);

// El resumen cita hallazgos por id: se ponen sus títulos ya traducidos («A» and «B»).
function summaryParams(ref, findings) {
  const titles = (ref.params?.top ?? []).map((id) => findings.find((f) => f.id === id)?.title ?? id).map((x) => `“${x}”`);
  return { ...ref.params, top: titles.length === 2 ? `${titles[0]} and ${titles[1]}` : (titles[0] ?? '') };
}

// «Porque…» del veredicto: una frase con código o el texto llano de una regla.
function because(verdict, findings) {
  const ref = verdict.becauseRef;
  if (ref?.code !== 'rule') return viaRef(ref, verdict.because);
  const f = findings.find((x) => x.id === ref.id);
  return f ? f.plain || f.title : verdict.because;
}

function localizeVerdict(verdict, findings) {
  if (!verdict) return verdict;
  const codes = Array.isArray(verdict.stepCodes) ? verdict.stepCodes : [];
  return {
    ...verdict,
    headline: verdict.headlineCode ? tr(verdict.headlineCode, {}, verdict.headline) : verdict.headline,
    because: because(verdict, findings),
    steps: (verdict.steps ?? []).map((step, i) => (codes[i] ? tr(codes[i], {}, step) : step)),
    top: (verdict.top ?? []).map(localizeFinding),
  };
}

function localizeAuth(auth) {
  if (!auth) return auth;
  const out = { ...auth };
  for (const k of ['spf', 'dkim', 'dmarc']) if (auth[k]) out[k] = { ...auth[k], detail: viaRef(auth[k].detailRef, auth[k].detail) };
  if (Array.isArray(auth.headers)) out.headers = auth.headers.map((h) => ({ ...h, why: viaRef(h.whyRef, h.why) }));
  return out;
}

/** Copia del informe con los textos en el idioma activo. */
export function localizeReport(report) {
  if (!report || getLang() === 'es') return report;
  const out = { ...report };
  if (report.level) out.label = tr(`level.${report.level}`, {}, report.label);
  if (Array.isArray(report.categories)) out.categories = report.categories.map(relabel('category'));
  if (Array.isArray(report.correlations)) out.correlations = report.correlations.map(relabel('correlation'));
  if (Array.isArray(report.findings)) out.findings = report.findings.map(localizeFinding);
  const findings = out.findings ?? [];
  if (report.summaryRef?.code) out.summary = tr(report.summaryRef.code, summaryParams(report.summaryRef, findings), report.summary);
  if (report.mainReasonRef) out.mainReason = viaRef(report.mainReasonRef, report.mainReason);
  if (report.verdict) out.verdict = localizeVerdict(report.verdict, findings);
  if (report.confidence) {
    const codes = report.confidence.codes ?? [];
    out.confidence = { ...report.confidence, reasons: (report.confidence.reasons ?? []).map((x, i) => (codes[i] ? tr(codes[i], {}, x) : x)) };
  }
  if (report.auth) out.auth = localizeAuth(report.auth);
  return out;
}

/** Claves que tr() no ha podido usar en inglés, con su motivo («rule.x.title: falta {brand}»). Para tests. */
export function missingEnglish(report) {
  const missing = [];
  const check = (key, params) => { const p = trProblem(key, params); if (p) missing.push(`${key}: ${p}`); };
  if (report?.level) check(`level.${report.level}`, {});
  for (const c of report?.categories ?? []) check(`category.${c.id}`, {});
  for (const c of report?.correlations ?? []) check(`correlation.${c.id}`, {});
  for (const f of report?.findings ?? []) if (translatable(f)) for (const [, key, params] of findingParts(f)) check(key, params);
  const checkRef = (where, ref) => { const p = refProblem(ref); if (p) missing.push(`${where} ${ref.code}: ${p}`); };
  if (report?.summaryRef) { const p = trProblem(report.summaryRef.code, summaryParams(report.summaryRef, report.findings ?? [])); if (p) missing.push(`summary ${report.summaryRef.code}: ${p}`); }
  checkRef('mainReason', report?.mainReasonRef);
  const v = report?.verdict;
  if (v) {
    check(v.headlineCode, {});
    if (v.becauseRef?.code !== 'rule') checkRef('because', v.becauseRef);
    for (const c of v.stepCodes ?? []) check(c, {});
  }
  for (const c of report?.confidence?.codes ?? []) check(c, {});
  for (const k of ['spf', 'dkim', 'dmarc']) checkRef(`auth.${k}`, report?.auth?.[k]?.detailRef);
  for (const h of report?.auth?.headers ?? []) checkRef('auth.header', h.whyRef);
  return missing;
}
