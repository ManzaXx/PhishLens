// Recomendaciones según el veredicto y las señales encontradas.

export function adviceFor(report) {
  const ids = new Set(report.findings.filter((f) => f.points > 0 && f.polarity !== 'trust').map((f) => f.id));
  const has = (prefix) => [...ids].some((id) => id.startsWith(prefix));

  if (report.level === 'safe') {
    return ['No hay señales claras, pero una nota baja no garantiza que sea seguro: si te piden datos o dinero, compruébalo por otra vía.'];
  }
  const advice = ['No pulses los enlaces ni respondas al mensaje.'];
  if (has('attachments.') || ids.has('links.download')) advice.push('No abras ni descargues el adjunto: puede instalar malware al abrirlo.');
  if (ids.has('language.credentials') || ids.has('html.form')) {
    advice.push('Si ya escribiste tu contraseña o tus datos, cambia la contraseña cuanto antes y activa la verificación en dos pasos.');
  }
  if (ids.has('sender.brand-impersonation') || ids.has('sender.mixed-script') || has('lookalike.')) {
    advice.push('Si dudas, contacta con la empresa por su web o teléfono oficial, nunca con los datos del email.');
  }
  advice.push('Repórtalo como phishing en tu gestor de correo. En España puedes consultar a INCIBE en el 017 (gratuito y confidencial).');
  return advice;
}
