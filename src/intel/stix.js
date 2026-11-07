// Exportación STIX 2.1 (spec 2.3, §5.4). Devuelve un objeto bundle: la UI lo serializa con JSON.stringify
// y aquí nunca se concatena JSON. Los ids son UUIDv5 deterministas:
// - los observables (SCO) usan el namespace oficial de STIX y sus propiedades de identidad (STIX 2.1 §2.9),
//   así OpenCTI o MISP reconocen el mismo dominio venga de donde venga;
// - indicadores, técnicas, campañas y relaciones usan el namespace propio de PhishLens.
import { uuidv5 } from '../lib/uuid.js';
import { registrableDomain } from '../parser/url.js';
import { BRANDS } from '../data/brands.js';
import { URL_SHORTENERS, TRACKING_DOMAINS, FREE_MAIL_DOMAINS, SOCIAL_DOMAINS, HOSTING_PLATFORMS } from '../data/lists.js';

export const STIX_SCO_NAMESPACE = '00abedb4-aa42-466c-9c01-fed23315a9b7';
export const PHISHLENS_NAMESPACE = 'f3a9c2d1-5b7e-4c8a-9d2f-6e1b0a7c4d53';

const SEVERE = new Set(['phishing', 'critical']);
const HASH_PREFERENCE = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'];
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// Dominios que aparecen en correos de phishing sin ser del atacante: no se marcan como maliciosos.
const BENIGN = new Set([...BRANDS.flatMap((b) => b.domains), ...URL_SHORTENERS, ...TRACKING_DOMAINS, ...FREE_MAIL_DOMAINS, ...SOCIAL_DOMAINS, ...HOSTING_PLATFORMS]
  .map((d) => registrableDomain(d)));
const isBenign = (host) => BENIGN.has(registrableDomain(host));

/** JSON canónico (claves ordenadas, sin espacios), como pide STIX para calcular ids. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().filter((k) => value[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Propiedades de identidad de cada observable (STIX 2.1, §6). */
function idContributing(type, props) {
  if (type === 'file') {
    const alg = HASH_PREFERENCE.find((a) => props.hashes?.[a]);
    return { hashes: alg ? { [alg]: props.hashes[alg] } : undefined, name: props.name };
  }
  if (type === 'email-message') return { from_ref: props.from_ref, subject: props.subject, body: props.body };
  return { value: props.value };
}

/** Id determinista de un observable, igual al de la librería oficial stix2. */
export const scoId = (type, props) => `${type}--${uuidv5(STIX_SCO_NAMESPACE, canonical(idContributing(type, props)))}`;
const sdoId = (type, name) => `${type}--${uuidv5(PHISHLENS_NAMESPACE, `${type}|${name}`)}`;

const escape = (v) => String(v).replaceAll('\\', '\\\\').replaceAll("'", "\\'");

/** Patrón STIX de un IOC. Los valores van siempre escapados (\ y '). */
export function stixPattern(type, value) {
  if (type === 'file-sha256') return `[file:hashes.'SHA-256' = '${escape(value)}']`;
  return `[${type}:value = '${escape(value)}']`;
}

const LABELS = { url: 'URL', 'domain-name': 'Dominio', 'ipv4-addr': 'IP', 'ipv6-addr': 'IP', 'email-addr': 'Dirección de correo', file: 'Adjunto' };
const REASONS = { 'sender-domain': 'dominio de envío', 'entry-ip': 'IP de entrada', 'link-domain': 'dominio en los enlaces', sha256: 'adjunto', template: 'plantilla' };

function list(words) {
  return words.length > 1 ? `${words.slice(0, -1).join(', ')} y ${words.at(-1)}` : words[0] ?? '';
}

function isoDate(text) {
  const d = new Date(String(text ?? ''));
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/**
 * @param {Array<{key, name, report}>} entries un correo, una URL o un lote
 * @param {{campaigns?: Array, now?: Date}} options
 */
export function toStixBundle(entries, { campaigns = [], now = new Date() } = {}) {
  const stamp = now.toISOString();
  const objects = new Map();
  const add = (o) => {
    if (!objects.has(o.id)) objects.set(o.id, o);
    return o.id;
  };
  const sco = (type, props) => add({ type, spec_version: '2.1', id: scoId(type, props), ...props });
  const sdo = (type, name, props) => add({ type, spec_version: '2.1', id: sdoId(type, name), created: stamp, modified: stamp, ...props });
  const relate = (type, source, target) => sdo('relationship', `${type}|${source}|${target}`, { relationship_type: type, source_ref: source, target_ref: target });
  const indicatorsOf = new Map(); // clave del correo -> ids de sus indicadores

  for (const { key, report } of [...entries].sort((a, b) => cmp(a.key, b.key))) {
    const email = report?.email ?? {};
    const iocs = report?.iocs ?? {};
    const severe = SEVERE.has(report?.level);
    const mine = [];
    const indicator = (type, value, observable, patternType = type) => {
      const pattern = stixPattern(patternType, value);
      const id = sdo('indicator', pattern, {
        name: `${LABELS[type]}: ${value}`,
        description: `Visto en un correo que PhishLens clasifica como «${report.label ?? report.level}».`,
        indicator_types: ['malicious-activity'],
        pattern,
        pattern_type: 'stix',
        valid_from: stamp,
      });
      relate('based-on', id, observable);
      mine.push(id);
    };

    for (const value of iocs.urls ?? []) {
      const id = sco('url', { value });
      let host = '';
      try {
        host = new URL(value).hostname;
      } catch { /* una URL rara no es indicador */ }
      if (severe && host && !isBenign(host.replace(/^\[|\]$/g, ''))) indicator('url', value, id);
    }
    for (const value of iocs.domains ?? []) {
      const id = sco('domain-name', { value });
      if (severe && !isBenign(value)) indicator('domain-name', value, id);
    }
    for (const raw of iocs.ips ?? []) {
      const value = String(raw).replace(/^\[|\]$/g, '');
      const type = value.includes(':') ? 'ipv6-addr' : 'ipv4-addr';
      const id = sco(type, { value });
      if (severe) indicator(type, value, id);
    }
    for (const value of iocs.emails ?? []) {
      const id = sco('email-addr', { value });
      if (severe) indicator('email-addr', value, id);
    }

    const attachmentRisk = (report?.findings ?? []).some((f) => f.category === 'attachments' && f.severity === 'high');
    const files = [];
    for (const a of email.attachments ?? []) {
      if (!a.sha256) continue;
      const hashes = { 'SHA-256': a.sha256, ...(a.sha1 ? { 'SHA-1': a.sha1 } : {}), ...(a.md5 ? { MD5: a.md5 } : {}) };
      const props = { hashes, ...(a.filename ? { name: a.filename } : {}), ...(Number.isFinite(a.size) ? { size: a.size } : {}) };
      const id = sco('file', props);
      files.push({ id, name: a.filename });
      if (severe || attachmentRisk) indicator('file', a.sha256, id, 'file-sha256');
    }

    if (email.from?.address) {
      const fromRef = sco('email-addr', { value: email.from.address });
      sco('email-message', {
        is_multipart: files.length > 0,
        from_ref: fromRef,
        ...(email.subject ? { subject: email.subject } : {}),
        ...(isoDate(email.date) ? { date: isoDate(email.date) } : {}),
        ...(files.length ? { body_multipart: files.map((f) => ({ body_raw_ref: f.id, content_disposition: `attachment; filename=${JSON.stringify(f.name ?? '')}` })) } : {}),
      });
    }

    for (const t of report?.techniques ?? []) {
      const ap = attackPattern(sdo, t);
      for (const ind of mine) relate('indicates', ind, ap);
    }
    indicatorsOf.set(key, mine);
  }

  for (const c of campaigns) {
    const kinds = [...new Set(c.reasons.map((r) => REASONS[r.type]).filter(Boolean))];
    const id = sdo('campaign', c.id, { name: c.name, description: `${c.emails.length} correos que comparten ${list(kinds)}.` });
    for (const t of c.techniques ?? []) relate('uses', id, attackPattern(sdo, t));
    for (const k of c.emails) for (const ind of indicatorsOf.get(k) ?? []) relate('indicates', ind, id);
  }

  const sorted = [...objects.values()].sort((a, b) => cmp(a.id, b.id));
  return { type: 'bundle', id: `bundle--${uuidv5(PHISHLENS_NAMESPACE, sorted.map((o) => o.id).join(','))}`, objects: sorted };
}

function attackPattern(sdo, t) {
  return sdo('attack-pattern', t.id, {
    name: t.name,
    external_references: [{ source_name: 'mitre-attack', external_id: t.id, url: t.url }],
  });
}
