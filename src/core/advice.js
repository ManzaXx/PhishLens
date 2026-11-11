// Recomendaciones según el veredicto y las señales encontradas. Cada consejo tiene un código
// (report.advice.*) para que la interfaz lo traduzca; aquí queda el texto en español.

const ADVICE = Object.freeze({
  'report.advice.safe': 'No hay señales claras, pero una nota baja no garantiza que sea seguro: si te piden datos o dinero, compruébalo por otra vía.',
  'report.advice.dont-click': 'No pulses los enlaces ni respondas al mensaje.',
  'report.advice.attachment': 'No abras ni descargues el adjunto: puede instalar malware al abrirlo.',
  'report.advice.password': 'Si ya escribiste tu contraseña o tus datos, cambia la contraseña cuanto antes y activa la verificación en dos pasos.',
  'report.advice.contact': 'Si dudas, contacta con la empresa por su web o teléfono oficial, nunca con los datos del email.',
  'report.advice.report': 'Repórtalo como phishing en tu gestor de correo. En España puedes consultar a INCIBE en el 017 (gratuito y confidencial).',
});

/** Códigos de los consejos para este informe, en orden. */
export function adviceCodesFor(report) {
  const ids = new Set(report.findings.filter((f) => f.points > 0 && f.polarity !== 'trust').map((f) => f.id));
  const has = (prefix) => [...ids].some((id) => id.startsWith(prefix));

  if (report.level === 'safe') return ['report.advice.safe'];
  const codes = ['report.advice.dont-click'];
  if (has('attachments.') || ids.has('links.download')) codes.push('report.advice.attachment');
  if (ids.has('language.credentials') || ids.has('html.form')) codes.push('report.advice.password');
  if (ids.has('sender.brand-impersonation') || ids.has('sender.mixed-script') || has('lookalike.')) codes.push('report.advice.contact');
  codes.push('report.advice.report');
  return codes;
}

export const adviceText = (code) => ADVICE[code];

export function adviceFor(report) {
  return adviceCodesFor(report).map(adviceText);
}
