// Detector de autenticación del remitente: SPF, DKIM y DMARC.
import { finding } from '../core/finding.js';
import { own } from '../lib/text.js';

export const name = 'auth';

const CHECKS = [
  {
    key: 'spf',
    label: 'SPF',
    detail: 'SPF comprueba que el servidor que envió el email está autorizado por el dominio. Si falla, el remitente puede estar falsificado.',
  },
  {
    key: 'dkim',
    label: 'DKIM',
    detail: 'DKIM es una firma digital del dominio. Si falla, el mensaje pudo ser modificado o no lo firmó quien dice ser.',
  },
  {
    key: 'dmarc',
    label: 'DMARC',
    detail: 'DMARC es la política del dominio sobre qué hacer si SPF y DKIM fallan. Un fallo de DMARC es una señal fuerte de suplantación.',
  },
];

const SEVERITY = { fail: 'high', permerror: 'medium', softfail: 'medium', temperror: 'low', none: 'low', neutral: 'low' };

export function detect(email) {
  if (!email.hasHeaders) return [];
  const results = email.headers.get('authentication-results') ?? [];
  if (results.length === 0) {
    return [finding({
      id: 'auth.missing',
      detector: name,
      severity: 'low',
      title: 'Sin resultados de autenticación',
      detail: 'El email no incluye la cabecera Authentication-Results, así que no se puede verificar SPF, DKIM ni DMARC.',
      evidence: 'Falta la cabecera Authentication-Results',
    })];
  }

  // La primera cabecera la añade el servidor que recibió el email (la más fiable).
  const header = results[0];
  const out = [];
  for (const check of CHECKS) {
    const m = new RegExp(`\\b${check.key}\\s*=\\s*([a-z]+)`, 'i').exec(header);
    if (!m) continue;
    const result = m[1].toLowerCase();
    const severity = own(SEVERITY, result);
    if (!severity) continue;
    out.push(finding({
      id: `auth.${check.key}`,
      detector: name,
      severity,
      title: `${check.label}: ${result}`,
      detail: check.detail,
      evidence: m[0],
    }));
  }
  return out;
}
