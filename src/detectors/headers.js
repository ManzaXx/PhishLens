// Detector de cabeceras técnicas: Message-ID, Date, X-Mailer y ruta Received.
import { finding } from './finding.js';
import { registrableDomain } from '../parser/url.js';

export const name = 'headers';

// Programas de envío masivo muy usados en kits de phishing.
const SUSPICIOUS_MAILERS = /(phpmailer|swiftmailer|leaf ?phpmailer|microsoft cdo|the bat!|python|smtp ?blast|gammadyne|mass ?mail)/i;
const DAY_MS = 24 * 60 * 60 * 1000;

/** Devuelve la ruta del email en orden de llegada: [{from, by, ip, date}] */
export function parseReceived(email) {
  // Se acota cada cabecera: un Received de megas con "(" sin cerrar no debe bloquear los regex.
  const hops = (email.headers?.get('received') ?? []).slice(0, 30).map((raw) => raw.slice(0, 1000)).map((value) => ({
    from: /\bfrom\s+(\S+)/i.exec(value)?.[1] ?? '',
    by: /\bby\s+([^\s;]+)/i.exec(value)?.[1] ?? '',
    // La IP que vio el servidor receptor va entre paréntesis: "from x (host [IP])".
    ip: (/\([^)]*\[([0-9a-f.:]+)\][^)]*\)/i.exec(value) ?? /\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*)\]/i.exec(value))?.[1] ?? '',
    date: value.includes(';') ? value.slice(value.lastIndexOf(';') + 1).trim() : '',
  }));
  // Cada servidor añade su Received arriba: el primero de la lista es el último salto.
  return hops.reverse();
}

export function detect(email, { now = Date.now() } = {}) {
  if (!email.hasHeaders) return [];
  const out = [];
  const fromDomain = email.from?.domain;

  const messageId = email.headers.get('message-id')?.[0];
  if (!messageId) {
    out.push(finding({
      id: 'headers.missing-messageid', detector: name, severity: 'low',
      title: 'Sin Message-ID',
      detail: 'Todo servidor de correo serio añade un identificador único. Su ausencia sugiere un envío hecho a mano o con un script.',
    }));
  } else if (fromDomain) {
    const idDomain = /@([^>\s]+)>?\s*$/.exec(messageId)?.[1]?.toLowerCase();
    if (idDomain && registrableDomain(idDomain) !== registrableDomain(fromDomain)) {
      out.push(finding({
        id: 'headers.messageid-domain', detector: name, severity: 'low',
        title: 'Message-ID de otro dominio',
        detail: `El identificador lo generó ${idDomain}, no ${fromDomain}. Es normal si se usa un proveedor de envío, pero también delata servidores ajenos.`,
        evidence: `Message-ID: ${messageId}`,
      }));
    }
  }

  const date = email.headers.get('date')?.[0];
  if (!date) {
    out.push(finding({
      id: 'headers.missing-date', detector: name, severity: 'low',
      title: 'Sin fecha de envío',
      detail: 'La cabecera Date es obligatoria. Su ausencia es típica de envíos automatizados mal construidos.',
    }));
  } else {
    const time = Date.parse(date);
    if (!Number.isNaN(time) && time - now > DAY_MS) {
      out.push(finding({
        id: 'headers.future-date', detector: name, severity: 'low',
        title: 'Fecha en el futuro',
        detail: 'Una fecha futura se usa para que el email quede arriba en la bandeja de entrada.',
        evidence: `Date: ${date}`,
      }));
    }
  }

  const mailer = email.headers.get('x-mailer')?.[0] ?? email.headers.get('user-agent')?.[0];
  if (mailer && SUSPICIOUS_MAILERS.test(mailer)) {
    out.push(finding({
      id: 'headers.mailer', detector: name, severity: 'medium',
      title: 'Enviado con una herramienta de envío masivo',
      detail: 'Este programa de envío aparece con mucha frecuencia en kits de phishing. Las empresas grandes usan sus propias plataformas.',
      evidence: mailer.slice(0, 120),
    }));
  }
  return out;
}
