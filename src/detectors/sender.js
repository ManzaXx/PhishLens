// Detector de remitente: incoherencias entre From, Reply-To y Return-Path y suplantación de marca.
import { finding } from '../core/finding.js';
import { registrableDomain } from '../parser/url.js';
import { parseAddress } from '../parser/eml.js';
import { BRANDS } from '../data/brands.js';
import { FREE_MAIL_DOMAINS } from '../data/lists.js';

export const name = 'sender';

const COUNTRY_SUFFIX = /^(?:[a-z]{2}|(?:co|com|org|net)\.[a-z]{2})$/;

export function isOfficialDomain(brand, domain) {
  const reg = registrableDomain(domain);
  if (brand.domains.some((d) => d === domain || d === reg || domain.endsWith(`.${d}`))) return true;
  if (!brand.ccTLD) return false;
  // amazon.fr, google.co.uk, outlook.es: misma etiqueta que un dominio oficial con sufijo de país.
  const [label, ...suffix] = reg.split('.');
  return COUNTRY_SUFFIX.test(suffix.join('.')) && brand.domains.some((d) => d.split('.')[0] === label);
}

export function brandInText(text) {
  const t = ` ${String(text).toLowerCase().replace(/[^a-z0-9áéíóúñ]+/g, ' ')} `;
  return BRANDS.find((b) => b.keywords.some((k) => t.includes(` ${k} `)));
}

// Letras latinas mezcladas con cirílicas o griegas dentro de la misma palabra.
// Dos regex simples por palabra: una sola con lookaheads anidados era cuadrática con nombres enormes.
const LATIN = /\p{Script=Latin}/u;
const CYRILLIC_GREEK = /[\p{Script=Cyrillic}\p{Script=Greek}]/u;
const isMixedScript = (word) => word.length <= 64 && LATIN.test(word) && CYRILLIC_GREEK.test(word);
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/;

function unicodeChecks(email) {
  const out = [];
  const fields = [['nombre del remitente', email.from?.name ?? ''], ['asunto', email.subject ?? '']];
  for (const [label, value] of fields) {
    const word = value.slice(0, 1000).split(/\s+/).find(isMixedScript);
    if (word) {
      out.push(finding({
        id: 'sender.mixed-script', detector: name, severity: 'high',
        title: 'Letras de otro alfabeto camufladas',
        detail: `El ${label} mezcla letras latinas con cirílicas o griegas que se ven idénticas. Es un truco para imitar una marca sin escribirla igual.`,
        evidence: `${word} → ${[...word].map((c) => (c.codePointAt(0) > 127 ? `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]` : c)).join('')}`,
      }));
      break;
    }
  }
  for (const [label, value] of fields) {
    if (INVISIBLE.test(value)) {
      out.push(finding({
        id: 'sender.invisible-chars', detector: name, severity: 'medium',
        title: 'Caracteres invisibles',
        detail: `El ${label} contiene caracteres invisibles. Se usan para que los filtros no reconozcan palabras como "PayPal" o "contraseña".`,
        evidence: value.replace(INVISIBLE, '⟦·⟧').slice(0, 120),
      }));
      break;
    }
  }
  return out;
}

// Dirección dentro del nombre visible. Clases sin solapamiento para que sea lineal.
// Letras de cualquier alfabeto: "seguridad@bbvа.es" con a cirílica también es una dirección.
const ADDRESS_IN_NAME = /[\p{L}\p{N}._%+-]+@([\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+)/gu;

function displayNameAddress(from, fromReg) {
  // NFKC convierte "＠" y las letras de ancho completo en sus equivalentes normales.
  const display = (from.name ?? '').slice(0, 1000).normalize('NFKC');
  for (const m of display.matchAll(ADDRESS_IN_NAME)) {
    if (registrableDomain(m[1]) === fromReg) continue;
    return [finding({
      id: 'sender.display-name-address', detector: name, severity: 'high',
      title: 'El nombre visible muestra otra dirección',
      detail: `El nombre del remitente es "${m[0]}", pero el correo viene en realidad de ${from.address}. Muchos móviles solo enseñan el nombre.`,
      evidence: `"${from.name}" <${from.address}>`,
    })];
  }
  return [];
}

function senderMismatch(email, fromReg) {
  const sender = parseAddress(email.headers?.get('sender')?.[0]);
  if (!sender?.domain) return [];
  const senderReg = registrableDomain(sender.domain);
  if (senderReg === fromReg) return [];
  const signed = (email.headers.get('dkim-signature') ?? [])
    .some((v) => registrableDomain(/(?:^|;)\s*d\s*=\s*([^;\s]+)/i.exec(v)?.[1] ?? '') === senderReg);
  if (signed) return [];
  return [finding({
    id: 'sender.sender-mismatch', detector: name, severity: 'low',
    title: 'Enviado en nombre de otro dominio (Sender)',
    detail: `La cabecera Sender dice que lo envió ${sender.domain} en nombre de ${email.from.domain}, y ${sender.domain} no lo ha firmado con DKIM. Es habitual en plataformas de envío, pero también en suplantaciones.`,
    evidence: `From: ${email.from.address} · Sender: ${sender.address}`,
  })];
}

export function detect(email) {
  const out = unicodeChecks(email);
  const from = email.from;
  if (!from || !from.domain) return out;
  const fromReg = registrableDomain(from.domain);

  if (email.replyTo?.domain && registrableDomain(email.replyTo.domain) !== fromReg) {
    out.push(finding({
      id: 'sender.replyto-mismatch',
      detector: name,
      severity: 'medium',
      title: 'Las respuestas van a otro dominio',
      detail: `Escribe desde ${from.domain}, pero si respondes tu email irá a ${email.replyTo.domain}.`,
      evidence: `From: ${from.address} · Reply-To: ${email.replyTo.address}`,
    }));
  }

  const rpDomain = email.returnPath?.split('@')[1];
  if (rpDomain && registrableDomain(rpDomain) !== fromReg) {
    out.push(finding({
      id: 'sender.returnpath-mismatch',
      detector: name,
      severity: 'low',
      title: 'Return-Path de otro dominio',
      detail: 'La dirección técnica de rebote no coincide con el remitente. Es habitual en newsletters, pero también en suplantaciones.',
      evidence: `From: ${from.address} · Return-Path: ${email.returnPath}`,
    }));
  }

  out.push(...displayNameAddress(from, fromReg), ...senderMismatch(email, fromReg));

  const brand = brandInText(from.name) ?? brandInText(from.address.split('@')[0]);
  if (brand && !isOfficialDomain(brand, from.domain)) {
    const free = FREE_MAIL_DOMAINS.has(from.domain);
    out.push(finding({
      id: 'sender.brand-impersonation',
      detector: name,
      severity: 'high',
      title: `Se hace pasar por ${brand.name}`,
      detail: free
        ? `Dice ser ${brand.name} pero escribe desde un correo gratuito (${from.domain}).`
        : `Dice ser ${brand.name} pero ${from.domain} no es un dominio oficial de ${brand.name} (${brand.domains[0]}).`,
      evidence: from.name ? `"${from.name}" <${from.address}>` : from.address,
    }));
  }
  return out;
}
