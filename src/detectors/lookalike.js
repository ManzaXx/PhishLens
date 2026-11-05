// Detector de dominios que imitan a marcas conocidas (typosquatting).
import { finding } from '../core/finding.js';
import { parseUrl, registrableDomain } from '../parser/url.js';
import { BRANDS } from '../data/brands.js';
import { isOfficialDomain } from './sender.js';
import { toUnicode } from '../parser/punycode.js';
import { sameShape, scriptsOf, foreignLookalikes } from '../parser/skeleton.js';

export const name = 'lookalike';

// Palabras demasiado genéricas para buscarlas dentro de otros dominios.
const GENERIC = new Set(['live', 'office', 'meta', 'mail', 'db']);
// Marcas que son palabras corrientes: solo cuentan como etiqueta exacta, nunca por parecido
// (grange ≠ orange).
const NO_FUZZY = new Set(['orange', 'ing', 'seur', 'gls', 'dgt', 'steam']);

const BRAND_KEYS = BRANDS.flatMap((brand) => {
  const keys = new Set(brand.domains.map((d) => registrableDomain(d).split('.')[0]));
  return [...keys].filter((k) => !GENERIC.has(k)).map((key) => ({ brand, key }));
});

export function levenshtein(a, b) {
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

export function normalizeHomoglyphs(s) {
  return s
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's');
}

// Distancia de edición permitida según la longitud de la marca: las marcas cortas
// solo se comparan tras normalizar homoglifos para evitar falsos positivos (ample ≠ apple).
function maxDistance(key) {
  if (key.length >= 8) return 2;
  if (key.length >= 6) return 1;
  return 0;
}

// Palabras de acceso que convierten "marca + palabra" en combosquatting.
const ACCESS_WORDS = new Set(['secure', 'login', 'signin', 'verify', 'account', 'update', 'support', 'cuenta', 'soporte', 'seguridad', 'acceso', 'verificar', 'cliente', 'clientes', 'pago', 'pagos']);

const OFFICIAL = BRANDS.flatMap((brand) => brand.domains.map((domain) => ({ brand, domain, hyphen: domain.replace(/\./g, '-') })));

/** El dominio oficial completo escrito a la izquierda de otro: paypal.com.evil.test, paypal-com.evil.test. */
function deceptiveSubdomain(host, reg) {
  const left = host.slice(0, host.length - reg.length);
  const dotted = `.${left}`;
  for (const o of OFFICIAL) {
    if (dotted.includes(`.${o.domain}.`)) return o;
    if (host.split('.').slice(0, -1).some((label) => `-${label}-`.includes(`-${o.hyphen}-`))) return o;
  }
  return null;
}

/** Devuelve {brand, domain, kind} si el dominio imita a una marca, o null. */
export function findLookalike(domain) {
  const host = String(domain ?? '').toLowerCase();
  if (!host || BRANDS.some((b) => isOfficialDomain(b, host))) return null;

  const reg = registrableDomain(host);
  const deceptive = deceptiveSubdomain(host, reg);
  if (deceptive) return { brand: deceptive.brand, domain: reg, kind: 'deceptive-subdomain', token: deceptive.domain };
  const labels = host.split('.').slice(0, -1);
  const tokens = new Set(labels.flatMap((l) => [l, ...l.split('-')]).filter(Boolean));

  for (const token of tokens) {
    const normalized = normalizeHomoglyphs(token);
    for (const { brand, key } of BRAND_KEYS) {
      // "cloud" está dentro de "icloud": es una palabra corriente, no una imitación.
      if (token === key || key.includes(token) || NO_FUZZY.has(key)) continue;
      if (normalized === key || (Math.abs(token.length - key.length) <= 2 && levenshtein(token, key) <= maxDistance(key) && levenshtein(token, key) > 0)) {
        return { brand, domain: reg, kind: 'typosquat', token };
      }
    }
  }
  // Las marcas que son palabras corrientes (ing, orange…) solo cuentan en la etiqueta que se
  // registra: www.ing.unipi.it es la facultad de ingeniería, no ING.
  const regTokens = new Set([reg.split('.')[0], ...reg.split('.')[0].split('-')]);
  for (const token of tokens) {
    const hit = BRAND_KEYS.find(({ key }) => key === token && (!NO_FUZZY.has(key) || regTokens.has(token)));
    if (hit) {
      const access = [...tokens].find((t) => ACCESS_WORDS.has(t)) ?? null;
      return { brand: hit.brand, domain: reg, kind: 'brand-in-domain', token, access };
    }
  }
  return null;
}

const LOOKALIKE_SCRIPTS = new Set(['Cyrillic', 'Greek', 'Armenian']);

/** Imitación con letras de otro alfabeto: { kind, brand, label, unicode } o null. */
export function findScriptSpoof(domain) {
  const ascii = String(domain ?? '').toLowerCase();
  const unicode = toUnicode(ascii);
  const labels = unicode.split('.').slice(0, -1);
  for (const label of labels) {
    const scripts = scriptsOf(label);
    const foreign = [...scripts].some((s) => LOOKALIKE_SCRIPTS.has(s));
    if (!foreign) continue;
    if (scripts.has('Latin')) return { kind: 'mixed-script-domain', brand: null, label, unicode };
    if (scripts.size === 1) {
      const hit = BRAND_KEYS.find(({ key }) => label.split('-').some((part) => sameShape(part, key)));
      if (hit) return { kind: 'whole-script', brand: hit.brand, label, unicode };
    }
  }
  // Homógrafos con letras latinas poco comunes (ɑ, ᴏ) o de alfabetos que no son cirílico, griego
  // ni armenio (cherokee, copto…): cualquier etiqueta no ASCII que se ve como una marca.
  for (const label of labels) {
    if (!/[^\x00-\x7f]/.test(label)) continue;
    const hit = BRAND_KEYS.find(({ key }) => label.split('-').some((part) => sameShape(part, key)));
    if (hit) return { kind: 'homoglyph', brand: hit.brand, label, unicode };
  }
  return null;
}

function lookalikeFinding(domain, hit, ctx) {
  const official = hit.brand.domains[0];
  if (hit.kind === 'deceptive-subdomain') {
    return finding({
      id: 'lookalike.deceptive-subdomain', detector: name, severity: 'high', ...ctx,
      title: `Subdominio que finge ser ${hit.brand.name}`,
      detail: `La dirección empieza por ${hit.token}, pero el dominio real es ${hit.domain}. Lo que cuenta es lo que hay justo antes del final, no al principio.`,
      evidence: domain,
    });
  }
  if (hit.kind === 'typosquat') {
    return finding({
      id: 'lookalike.typosquat', detector: name, severity: 'high', ...ctx,
      title: `Dominio que imita a ${hit.brand.name}`,
      detail: `${hit.domain} se parece mucho a ${official}, pero no es el mismo dominio.`,
      evidence: `${domain} ≈ ${official}`,
    });
  }
  return finding({
    id: 'lookalike.brand-in-domain', detector: name, severity: hit.access ? 'high' : 'medium', ...ctx,
    title: `Usa el nombre de ${hit.brand.name} en un dominio ajeno`,
    detail: hit.access
      ? `${hit.domain} junta "${hit.token}" con "${hit.access}" para parecer una página oficial de acceso, pero no pertenece a ${hit.brand.name} (${official}).`
      : `${hit.domain} contiene "${hit.token}" pero no pertenece a ${hit.brand.name} (${official}).`,
    evidence: hit.access ? `${domain} (marca + "${hit.access}")` : domain,
  });
}

function scriptFinding(domain, hit, ctx) {
  const letters = foreignLookalikes(hit.label);
  const shown = `${hit.unicode} (${domain})${letters.length ? ` · ${letters.slice(0, 6).join(' ')}` : ''}`;
  if (hit.kind === 'mixed-script-domain') {
    return finding({
      id: 'lookalike.mixed-script-domain', detector: name, severity: 'high', ...ctx,
      title: 'Dominio con letras de varios alfabetos',
      detail: `La parte «${hit.label}» mezcla letras latinas con otras cirílicas, griegas o armenias que se ven iguales. Ningún dominio legítimo necesita mezclarlas.`,
      evidence: shown,
    });
  }
  if (hit.kind === 'homoglyph') {
    return finding({
      id: 'lookalike.homoglyph', detector: name, severity: 'high', ...ctx,
      title: `Dominio con letras que imitan a ${hit.brand.name}`,
      detail: `«${hit.label}» usa caracteres que no son letras latinas normales, pero en pantalla se lee como ${hit.brand.domains[0]}.`,
      evidence: shown,
    });
  }
  return finding({
    id: 'lookalike.whole-script', detector: name, severity: 'high', ...ctx,
    title: `Dominio en otro alfabeto que imita a ${hit.brand.name}`,
    detail: `«${hit.label}» está escrito entero con letras de otro alfabeto, pero se lee como ${hit.brand.domains[0]}.`,
    evidence: shown,
  });
}

export function detect(email) {
  // Un dominio parecido en el From es suplantación del remitente; en un enlace, contenido.
  const domains = [];
  if (email.from?.domain) domains.push({ domain: email.from.domain, category: 'sender' });
  for (const link of email.links ?? []) {
    const url = parseUrl(link.href);
    if (url && !url.isIp) domains.push({ domain: url.hostname, category: 'links' });
  }

  const out = [];
  const seen = new Set();
  for (const { domain, category } of domains) {
    if (seen.size >= 10) break;
    const spoof = findScriptSpoof(domain);
    if (spoof) {
      const reg = registrableDomain(domain);
      if (!seen.has(reg)) out.push(scriptFinding(domain, spoof, { category, brand: spoof.brand?.name ?? null }));
      seen.add(reg);
      continue;
    }
    const hit = findLookalike(domain);
    if (!hit || seen.has(hit.domain)) continue;
    seen.add(hit.domain);
    out.push(lookalikeFinding(domain, hit, { category, brand: hit.brand.name }));
  }
  return out;
}
