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
  return out;
}

const relabel = (prefix) => (item) => (item?.id ? { ...item, label: tr(`${prefix}.${item.id}`, {}, item.label) } : item);

/** Copia del informe con los textos en el idioma activo. */
export function localizeReport(report) {
  if (!report || getLang() === 'es') return report;
  const out = { ...report };
  if (report.level) out.label = tr(`level.${report.level}`, {}, report.label);
  if (Array.isArray(report.categories)) out.categories = report.categories.map(relabel('category'));
  if (Array.isArray(report.correlations)) out.correlations = report.correlations.map(relabel('correlation'));
  if (Array.isArray(report.findings)) out.findings = report.findings.map(localizeFinding);
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
  return missing;
}
