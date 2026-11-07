// Detector de enlaces engañosos o sospechosos.
import { finding } from '../core/finding.js';
import { parseUrl, registrableDomain } from '../parser/url.js';
import { analyzeUrl, chainText } from '../intel/url.js';
import { URL_SHORTENERS, SUSPICIOUS_TLDS, TRACKING_DOMAINS, DANGEROUS_EXTENSIONS, ARCHIVE_EXTENSIONS, MACRO_EXTENSIONS } from '../data/lists.js';
import { BRANDS } from '../data/brands.js';
import { isOfficialDomain } from './sender.js';
import { toUnicode } from '../parser/punycode.js';
import { findScriptSpoof } from './lookalike.js';

export const name = 'links';

// Cuantificadores acotados para que un texto enorme no dispare el retroceso del regex.
const DOMAIN_IN_TEXT = /\b((?:[a-z0-9-]{1,63}\.){1,10}[a-z]{2,24})\b/i;
const MAX_TEXT = 300;
const LOGIN_PATH = /(log[-_]?in|sign[-_]?in|acceso|cuenta|account|verif|password|contrase|banca|secure)/i;

/** Reglas de la URL desenvuelta (spec 2.3, §5.3). Cada una lleva la cadena como evidencia. */
function urlChecks(a) {
  const out = [];
  const chain = chainText(a);
  const hosts = a.hops.map((h) => new URL(h.href).hostname);
  const jumps = a.hops.length - 1;
  if (a.flags.nestedRedirect) {
    out.push(['nested-redirect', 'medium', 'Enlace que pasa por varias webs antes de llegar',
      `El enlace salta ${jumps} veces antes de llegar a ${a.hostname}: así se esconde el destino real.`, chain]);
  }
  if (a.flags.openRedirect) {
    out.push(['open-redirect', 'medium', 'Enlace que se aprovecha de otra web',
      `El enlace empieza en ${hosts[0]}, pero esa web te reenvía a ${a.hostname}. Se usa una web conocida para parecer de fiar.`, chain]);
  }
  if (a.flags.obfuscatedIp) {
    out.push(['obfuscated-ip', 'high', 'Dirección IP disfrazada',
      `El enlace escribe la dirección ${a.hostname} de una forma rara para que no parezca una IP.`, chain]);
  }
  if (a.flags.credentials) {
    out.push(['credentials-in-url', 'high', 'Enlace con usuario y contraseña dentro',
      `El enlace lleva un usuario y una contraseña antes de ${a.hostname}. Ninguna web seria los pone ahí: sirve para engañar o para colar un acceso robado.`, chain]);
  }
  if (a.flags.highEntropy) {
    out.push(['high-entropy', 'low', 'Dirección con aspecto aleatorio',
      `${a.hostname} o su ruta parecen escritos al azar, algo típico de webs de usar y tirar.`, chain]);
  }
  if (a.flags.nonStandardPort) {
    out.push(['non-standard-port', 'low', 'Enlace con un puerto poco habitual',
      `El enlace usa el puerto ${a.port}. Las webs normales no lo indican.`, chain]);
  }
  return out;
}

function checksFor(link, url, analysis) {
  const out = [];
  const shown = link.text !== link.href ? DOMAIN_IN_TEXT.exec(link.text.slice(0, MAX_TEXT))?.[1] : null;
  if (shown && registrableDomain(shown) !== url.registrableDomain) {
    if (TRACKING_DOMAINS.has(url.registrableDomain)) {
      out.push(['tracking', 'low', 'Enlace de seguimiento',
        `El enlace pasa por ${url.registrableDomain}, una plataforma de email marketing que mide los clics. Es habitual en newsletters legítimas, pero oculta el destino final.`]);
    } else {
      out.push(['mismatch', 'high', 'El enlace no lleva a donde dice',
        `El texto muestra ${shown.toLowerCase()}, pero al pulsar irías a ${url.hostname}.`]);
    }
  }
  if (url.hasAt && !analysis.flags.credentials) {
    out.push(['at-sign', 'high', 'URL con @ que oculta el destino real',
      `Todo lo que va antes de la @ se ignora: el navegador iría a ${url.hostname}.`]);
  }
  if (url.isIp) {
    out.push(['ip', 'high', 'Enlace a una dirección IP',
      'Las empresas legítimas usan nombres de dominio, no direcciones IP.']);
  }
  if (url.isPunycode) {
    // Grave solo si las letras imitan a otras (eso lo detalla lookalike); un IDN normal es leve.
    const spoof = findScriptSpoof(url.hostname);
    out.push(['punycode', spoof ? 'high' : 'low', 'Dominio con caracteres internacionales (punycode)',
      spoof
        ? `${url.hostname} es en realidad ${toUnicode(url.hostname)}: usa letras de otros alfabetos que parecen latinas.`
        : `${url.hostname} es ${toUnicode(url.hostname)}, un dominio con letras no inglesas. Comprueba que es el que esperas.`]);
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
  const ext = /\.([a-z0-9]{2,5})$/i.exec(url.pathOnly)?.[1]?.toLowerCase();
  if (ext && (DANGEROUS_EXTENSIONS.has(ext) && !['html', 'htm', 'com'].includes(ext) || ARCHIVE_EXTENSIONS.has(ext) || MACRO_EXTENSIONS.has(ext))) {
    const severe = DANGEROUS_EXTENSIONS.has(ext);
    out.push(['download', severe ? 'high' : 'medium', 'Enlace que descarga un archivo',
      `Al pulsar se descargaría un .${ext}${severe ? ', un tipo de archivo que puede ejecutar programas' : ''}.`]);
  }
  if (url.protocol === 'http' && LOGIN_PATH.test(url.path)) {
    out.push(['insecure-login', 'medium', 'Página de acceso sin HTTPS',
      'Un formulario de acceso sin cifrar no lo usaría ninguna empresa seria.']);
  }
  return out;
}

export function detect(email) {
  // Un hallazgo por tipo de señal: con 200 enlaces iguales el informe sigue siendo legible.
  const byId = new Map();
  for (const link of email.links ?? []) {
    // Si el enlace está envuelto (Safe Links, Google, un redirector...) se analiza el destino real.
    const analysis = analyzeUrl(link.href);
    if (!analysis) continue;
    const real = analysis.hops.length > 1 ? analysis.final : null;
    const target = analysis.final;
    const url = parseUrl(target);
    if (!url) continue;
    const shownText = link.text === link.href ? target : link.text;
    for (const [id, severity, title, detail, chain] of [...checksFor({ text: shownText, href: target }, url, analysis), ...urlChecks(analysis)]) {
      const entry = byId.get(id);
      if (entry) {
        entry.hrefs.add(url.href);
        continue;
      }
      byId.set(id, {
        hrefs: new Set([url.href]),
        severity,
        title,
        detail,
        evidence: chain ?? (link.text !== link.href ? `"${link.text}" → ` : '') + (real ? `${real} (envuelto en ${new URL(analysis.hops[0].href).hostname})` : link.href),
      });
    }
  }
  return [...byId].map(([id, e]) => finding({
    id: `links.${id}`,
    detector: name,
    severity: e.severity,
    title: e.hrefs.size > 1 ? `${e.title} (${e.hrefs.size} enlaces)` : e.title,
    detail: e.detail,
    evidence: e.evidence,
  }));
}
