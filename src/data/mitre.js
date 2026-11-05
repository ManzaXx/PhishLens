// Correspondencia entre hallazgos y técnicas de MITRE ATT&CK (https://attack.mitre.org).
//
// Versión fijada: Enterprise ATT&CK 20.1 (2026-11-05).
// Fuente: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json
// sha256 539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5, comprobado el 2026-11-05
// con `node tools/check-mitre.mjs RUTA_AL_JSON` (ids existentes, no revocados, nombre y táctica).
// En la 20.0, T1656 (Impersonation) y T1672 (Email Spoofing) se revocaron en favor de
// T1684.001 y T1684.002, y la táctica Defense Evasion pasó a llamarse Stealth.

export const ATTACK_VERSION = '20.1';

export const TECHNIQUES = Object.freeze({
  'T1566': { name: 'Phishing', tactic: 'Initial Access', why: 'El correo es el vector de entrada del ataque.' },
  'T1566.001': { name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access', why: 'El ataque llega en un adjunto del correo.' },
  'T1566.002': { name: 'Phishing: Spearphishing Link', tactic: 'Initial Access', why: 'El ataque llega en un enlace del correo.' },
  'T1598': { name: 'Phishing for Information', tactic: 'Reconnaissance', why: 'El correo intenta que la víctima entregue datos o contraseñas.' },
  'T1684.001': { name: 'Social Engineering: Impersonation', tactic: 'Stealth', why: 'El remitente se hace pasar por una marca o persona de confianza.' },
  'T1684.002': { name: 'Social Engineering: Email Spoofing', tactic: 'Stealth', why: 'Las cabeceras del correo están falseadas para fingir otro origen.' },
  'T1583.001': { name: 'Acquire Infrastructure: Domains', tactic: 'Resource Development', why: 'El atacante registró un dominio que imita a uno legítimo.' },
  'T1036.002': { name: 'Masquerading: Right-to-Left Override', tactic: 'Stealth', why: 'Un carácter invisible da la vuelta al nombre del archivo para ocultar su extensión real.' },
  'T1036.007': { name: 'Masquerading: Double File Extension', tactic: 'Stealth', why: 'Una doble extensión esconde que el archivo es ejecutable.' },
  'T1027': { name: 'Obfuscated Files or Information', tactic: 'Stealth', why: 'El contenido se oculta o se ofusca para burlar filtros y miradas.' },
  'T1204': { name: 'User Execution', tactic: 'Execution', why: 'El mensaje presiona a la víctima para que actúe sin pensar.' },
  'T1204.001': { name: 'User Execution: Malicious Link', tactic: 'Execution', why: 'El ataque necesita que la víctima pulse el enlace.' },
  'T1204.002': { name: 'User Execution: Malicious File', tactic: 'Execution', why: 'El ataque necesita que la víctima abra el archivo.' },
  'T1059.007': { name: 'Command and Scripting Interpreter: JavaScript', tactic: 'Execution', why: 'El correo incluye código JavaScript.' },
});

// Del más concreto al más general: gana la primera regla que coincide. [] = sin técnica.
const RULES = [
  [/^attachments\.double-extension$/, ['T1036.007', 'T1204.002']],
  [/^attachments\.rtl-override$/, ['T1036.002', 'T1204.002']],
  [/^attachments\.(dangerous|macro|archive)$/, ['T1566.001', 'T1204.002']],
  [/^attachments\./, ['T1566.001']],
  [/^links\./, ['T1566.002', 'T1204.001']],
  [/^lookalike\./, ['T1583.001']],
  [/^auth\.(dkim-body-verified|dkim-verified-aligned|dkim-weak)$/, []],
  [/^auth\./, ['T1684.002']],
  [/^sender\.(brand-impersonation|mixed-script|display-name-address)$/, ['T1684.001']],
  [/^sender\.invisible-chars$/, ['T1027']],
  [/^sender\./, ['T1566']],
  [/^html\.(form|data-uri)$/, ['T1598']],
  [/^html\.script$/, ['T1059.007']],
  [/^html\./, ['T1027']],
  [/^language\.credentials$/, ['T1598']],
  [/^language\./, ['T1204']],
  [/^headers\.duplicate-from$/, ['T1684.002']],
  // Ambigüedades MIME que hacen que el filtro y el usuario vean cosas distintas.
  [/^mime\.(duplicate-content-type|boundary-reuse|boundary-in-content|charset-conflict)$/, ['T1027']],
  // Received inventados para fingir otro origen.
  [/^route\.(helo-mismatch|private-ip-boundary|time-travel)$/, ['T1684.002']],
];

/** Datos completos de una técnica, con su URL oficial. */
export function technique(id) {
  const t = TECHNIQUES[id];
  if (!t) return null;
  const [base, sub] = id.split('.');
  return { id, ...t, url: `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ''}` };
}

/** Técnicas ATT&CK asociadas a un id de hallazgo (puede ser una lista vacía). */
export function techniquesFor(findingId) {
  const rule = RULES.find(([re]) => re.test(findingId));
  return (rule?.[1] ?? []).map(technique);
}

/** La primera técnica, o null (compatibilidad con la v2.1). */
export function techniqueFor(findingId) {
  return techniquesFor(findingId)[0] ?? null;
}

/** Todos los ids que usan las reglas (para tools/check-mitre.mjs). */
export const USED_IDS = [...new Set(RULES.flatMap(([, ids]) => ids))];
