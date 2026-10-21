// Detector de remitente: incoherencias entre From, Reply-To y Return-Path y suplantación de marca.
import { finding } from './finding.js';
import { registrableDomain } from '../parser/url.js';
import { BRANDS } from '../data/brands.js';
import { FREE_MAIL_DOMAINS } from '../data/lists.js';

export const name = 'sender';

export function isOfficialDomain(brand, domain) {
  const reg = registrableDomain(domain);
  return brand.domains.some((d) => d === domain || d === reg || domain.endsWith(`.${d}`));
}

export function brandInText(text) {
  const t = ` ${String(text).toLowerCase().replace(/[^a-z0-9áéíóúñ]+/g, ' ')} `;
  return BRANDS.find((b) => b.keywords.some((k) => t.includes(` ${k} `)));
}

export function detect(email) {
  const from = email.from;
  if (!from || !from.domain) return [];
  const out = [];
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
