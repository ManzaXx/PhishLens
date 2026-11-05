// Correspondencia entre hallazgos y técnicas de MITRE ATT&CK (https://attack.mitre.org).

const TECHNIQUES = {
  'T1566': 'Phishing',
  'T1566.001': 'Phishing: Spearphishing Attachment',
  'T1566.002': 'Phishing: Spearphishing Link',
  'T1598': 'Phishing for Information',
  'T1656': 'Impersonation',
  'T1672': 'Email Spoofing',
  'T1583.001': 'Acquire Infrastructure: Domains',
  'T1036.002': 'Masquerading: Right-to-Left Override',
  'T1036.007': 'Masquerading: Double File Extension',
  'T1027': 'Obfuscated Files or Information',
  'T1204': 'User Execution',
  'T1059.007': 'Command and Scripting Interpreter: JavaScript',
};

// Del más concreto al más general: gana la primera regla que coincide.
const RULES = [
  [/^attachments\.double-extension$/, 'T1036.007'],
  [/^attachments\.rtl-override$/, 'T1036.002'],
  [/^attachments\./, 'T1566.001'],
  [/^links\./, 'T1566.002'],
  [/^lookalike\./, 'T1583.001'],
  [/^auth\.(dkim-body-verified|dkim-weak)$/, null],
  [/^auth\./, 'T1672'],
  [/^sender\.(brand-impersonation|mixed-script)$/, 'T1656'],
  [/^sender\.invisible-chars$/, 'T1027'],
  [/^sender\./, 'T1566'],
  [/^html\.(form|data-uri)$/, 'T1598'],
  [/^html\.script$/, 'T1059.007'],
  [/^html\./, 'T1027'],
  [/^language\.credentials$/, 'T1598'],
  [/^language\./, 'T1204'],
  [/^headers\./, 'T1566'],
  [/^route\.helo-mismatch$/, 'T1672'],
];

/** Técnica ATT&CK asociada a un id de hallazgo, o null. */
export function techniqueFor(findingId) {
  const rule = RULES.find(([re]) => re.test(findingId));
  const id = rule?.[1];
  if (!id) return null;
  return { id, name: TECHNIQUES[id], url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` };
}
