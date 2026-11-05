// Extracción de indicadores de compromiso (IOCs) para compartir con un equipo de seguridad.
import { parseUrl, unwrapUrl } from '../parser/url.js';
import { parseReceived } from '../parser/received.js';

const PRIVATE_IP = /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/;

/** "Desactiva" un indicador para que no sea clicable: hxxp://evil[.]com */
export function defang(value) {
  return String(value)
    .replace(/^http/i, (m) => (m[0] === 'H' ? 'HXXP' : 'hxxp'))
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]');
}

export function extractIocs(email) {
  const urls = new Set();
  const domains = new Set();
  const ips = new Set();
  const emails = new Set();
  const attachments = new Set();
  const hashes = new Set();

  const addEmail = (address) => {
    if (!address || !address.includes('@')) return;
    emails.add(address);
    domains.add(address.split('@')[1]);
  };
  addEmail(email.from?.address);
  addEmail(email.replyTo?.address);
  addEmail(email.returnPath);

  for (const link of email.links ?? []) {
    const href = unwrapUrl(link.href) ?? link.href;
    const url = parseUrl(href);
    if (!url) continue;
    urls.add(url.href);
    (url.isIp ? ips : domains).add(url.hostname);
  }
  for (const hop of parseReceived(email)) {
    if (hop.ip && !PRIVATE_IP.test(hop.ip) && hop.ip.includes('.')) ips.add(hop.ip);
  }
  for (const a of email.attachments ?? []) {
    attachments.add(a.filename);
    if (a.sha256) hashes.add(a.sha256);
  }

  return {
    urls: [...urls],
    domains: [...domains],
    ips: [...ips],
    emails: [...emails],
    attachments: [...attachments],
    hashes: [...hashes],
  };
}

// Nombres de fichero y hashes no son clicables: se copian tal cual.
export const PLAIN = new Set(['attachments', 'hashes']);

const SECTIONS = [['urls', 'URLs'], ['domains', 'Dominios'], ['ips', 'IPs'], ['emails', 'Emails'], ['attachments', 'Adjuntos'], ['hashes', 'SHA-256']];

/** Texto plano con los IOCs "defanged", listo para pegar en un ticket. */
export function iocsToText(iocs) {
  return SECTIONS
    .filter(([key]) => iocs[key]?.length)
    .map(([key, label]) => `# ${label}\n${iocs[key].map((v) => (PLAIN.has(key) ? v : defang(v))).join('\n')}`)
    .join('\n\n');
}
