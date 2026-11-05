// Detector de cabeceras técnicas: Message-ID, Date, X-Mailer y ruta Received.
import { finding } from '../core/finding.js';
import { registrableDomain } from '../parser/url.js';

export const name = 'headers';

// Programas de envío masivo muy usados en kits de phishing.
const SUSPICIOUS_MAILERS = /(phpmailer|swiftmailer|leaf ?phpmailer|microsoft cdo|the bat!|python|smtp ?blast|gammadyne|mass ?mail)/i;
const DAY_MS = 24 * 60 * 60 * 1000;

// Cabeceras que deben aparecer una sola vez (RFC 5322 §3.6).
const SINGLE = ['subject', 'date', 'to', 'message-id', 'sender'];
const DISPLAY = { subject: 'Subject', date: 'Date', to: 'To', 'message-id': 'Message-ID', sender: 'Sender' };

function duplicates(email) {
  const count = new Map();
  for (const h of email.headerList ?? []) count.set(h.name, (count.get(h.name) ?? 0) + 1);
  const out = [];
  if ((count.get('from') ?? 0) > 1) {
    out.push(finding({
      id: 'headers.duplicate-from', detector: name, severity: 'high',
      title: 'El correo tiene varios remitentes (From)',
      detail: 'Cada programa de correo puede enseñar un From distinto: tú ves uno y el filtro antispam comprobó otro. Es una técnica para burlar la autenticación.',
      evidence: email.headers.get('from').slice(0, 5).join(' · ').slice(0, 300),
      reliability: 'high',
    }));
  }
  const repeated = SINGLE.filter((h) => (count.get(h) ?? 0) > 1);
  if (repeated.length) {
    out.push(finding({
      id: 'headers.duplicate', detector: name, severity: 'medium',
      title: 'Cabeceras que deberían ser únicas aparecen repetidas',
      detail: 'Un correo bien formado solo lleva una de cada. Repetirlas sirve para que el cliente de correo y los filtros lean cosas distintas.',
      evidence: repeated.map((h) => `${DISPLAY[h]} ×${count.get(h)}`).join(', '),
      reliability: 'medium',
    }));
  }
  return out;
}

export function detect(email, { now = Date.now() } = {}) {
  if (!email.hasHeaders) return [];
  const out = duplicates(email);
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
