// Detector de enlaces engañosos o sospechosos.
import { finding } from './finding.js';
import { parseUrl, registrableDomain } from '../parser/url.js';
import { URL_SHORTENERS, SUSPICIOUS_TLDS } from '../data/lists.js';
import { BRANDS } from '../data/brands.js';
import { isOfficialDomain } from './sender.js';

export const name = 'links';

// Cuantificadores acotados para que un texto enorme no dispare el retroceso del regex.
const DOMAIN_IN_TEXT = /\b((?:[a-z0-9-]{1,63}\.){1,10}[a-z]{2,24})\b/i;
const MAX_TEXT = 300;
const LOGIN_PATH = /(log[-_]?in|sign[-_]?in|acceso|cuenta|account|verif|password|contrase|banca|secure)/i;

function checksFor(link, url) {
  const out = [];
  const shown = link.text !== link.href ? DOMAIN_IN_TEXT.exec(link.text.slice(0, MAX_TEXT))?.[1] : null;
  if (shown && registrableDomain(shown) !== url.registrableDomain) {
    out.push(['mismatch', 'high', 'El enlace no lleva a donde dice',
      `El texto muestra ${shown.toLowerCase()}, pero al pulsar irías a ${url.hostname}.`]);
  }
  if (url.hasAt) {
    out.push(['at-sign', 'high', 'URL con @ que oculta el destino real',
      `Todo lo que va antes de la @ se ignora: el navegador iría a ${url.hostname}.`]);
  }
  if (url.isIp) {
    out.push(['ip', 'high', 'Enlace a una dirección IP',
      'Las empresas legítimas usan nombres de dominio, no direcciones IP.']);
  }
  if (url.isPunycode) {
    out.push(['punycode', 'high', 'Dominio con caracteres internacionales (punycode)',
      `${url.hostname} usa letras de otros alfabetos que pueden parecer idénticas a las latinas.`]);
  }
  if (URL_SHORTENERS.has(url.registrableDomain) || URL_SHORTENERS.has(url.hostname)) {
    out.push(['shortener', 'medium', 'Enlace acortado',
      `${url.hostname} es un acortador: oculta el destino final del enlace.`]);
  }
  if (SUSPICIOUS_TLDS.has(url.tld)) {
    out.push(['tld', 'medium', `Dominio .${url.tld}`,
      `.${url.tld} es una extensión barata muy usada en campañas de phishing.`]);
  }
  const pathWords = ` ${url.path.toLowerCase().replace(/[^a-z0-9]+/g, ' ')} `;
  const brandInPath = BRANDS.find((b) => b.keywords.some((k) => !k.includes(' ') && pathWords.includes(` ${k} `)));
  if (brandInPath && !isOfficialDomain(brandInPath, url.hostname)) {
    out.push(['brand-in-path', 'medium', `Menciona a ${brandInPath.name} en un sitio ajeno`,
      `La ruta del enlace usa el nombre de ${brandInPath.name}, pero el sitio es ${url.hostname}.`]);
  }
  if (url.protocol === 'http' && LOGIN_PATH.test(url.path)) {
    out.push(['insecure-login', 'medium', 'Página de acceso sin HTTPS',
      'Un formulario de acceso sin cifrar no lo usaría ninguna empresa seria.']);
  }
  return out;
}

export function detect(email) {
  const out = [];
  const seen = new Set();
  for (const link of email.links ?? []) {
    const url = parseUrl(link.href);
    if (!url) continue;
    for (const [id, severity, title, detail] of checksFor(link, url)) {
      const key = `${id}|${url.href}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(finding({
        id: `links.${id}`,
        detector: name,
        severity,
        title,
        detail,
        evidence: link.text !== link.href ? `"${link.text}" → ${link.href}` : link.href,
      }));
    }
  }
  return out;
}
