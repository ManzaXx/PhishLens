// Detector de dominios que imitan a marcas conocidas (typosquatting).
import { finding } from './finding.js';
import { parseUrl, registrableDomain } from '../parser/url.js';
import { BRANDS } from '../data/brands.js';
import { isOfficialDomain } from './sender.js';

export const name = 'lookalike';

// Palabras demasiado genéricas para buscarlas dentro de otros dominios.
const GENERIC = new Set(['live', 'office', 'meta', 'mail']);

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

/** Devuelve {brand, domain, kind} si el dominio imita a una marca, o null. */
export function findLookalike(domain) {
  const host = String(domain ?? '').toLowerCase();
  if (!host || BRANDS.some((b) => isOfficialDomain(b, host))) return null;

  const reg = registrableDomain(host);
  const labels = host.split('.').slice(0, -1);
  const tokens = new Set(labels.flatMap((l) => [l, ...l.split('-')]).filter(Boolean));

  for (const token of tokens) {
    const normalized = normalizeHomoglyphs(token);
    for (const { brand, key } of BRAND_KEYS) {
      // "cloud" está dentro de "icloud": es una palabra corriente, no una imitación.
      if (token === key || key.includes(token)) continue;
      if (normalized === key || (Math.abs(token.length - key.length) <= 2 && levenshtein(token, key) <= maxDistance(key) && levenshtein(token, key) > 0)) {
        return { brand, domain: reg, kind: 'typosquat', token };
      }
    }
  }
  for (const token of tokens) {
    const hit = BRAND_KEYS.find(({ key }) => key === token);
    if (hit) return { brand: hit.brand, domain: reg, kind: 'brand-in-domain', token };
  }
  return null;
}

export function detect(email) {
  const domains = [];
  if (email.from?.domain) domains.push(email.from.domain);
  for (const link of email.links ?? []) {
    const url = parseUrl(link.href);
    if (url && !url.isIp) domains.push(url.hostname);
  }

  const out = [];
  const seen = new Set();
  for (const domain of domains) {
    const hit = findLookalike(domain);
    if (!hit || seen.has(hit.domain)) continue;
    seen.add(hit.domain);
    const official = hit.brand.domains[0];
    out.push(hit.kind === 'typosquat'
      ? finding({
        id: 'lookalike.typosquat',
        detector: name,
        severity: 'high',
        title: `Dominio que imita a ${hit.brand.name}`,
        detail: `${hit.domain} se parece mucho a ${official}, pero no es el mismo dominio.`,
        evidence: `${domain} ≈ ${official}`,
      })
      : finding({
        id: 'lookalike.brand-in-domain',
        detector: name,
        severity: 'medium',
        title: `Usa el nombre de ${hit.brand.name} en un dominio ajeno`,
        detail: `${hit.domain} contiene "${hit.token}" pero no pertenece a ${hit.brand.name} (${official}).`,
        evidence: domain,
      }));
  }
  return out;
}
