// Listas de referencia usadas por los detectores.

export const FREE_MAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'hotmail.com', 'hotmail.es', 'outlook.com', 'outlook.es',
  'live.com', 'yahoo.com', 'yahoo.es', 'aol.com', 'gmx.com', 'gmx.es', 'mail.com',
  'protonmail.com', 'proton.me', 'icloud.com', 'zoho.com', 'yandex.com', 'tutanota.com',
]);

export const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
  'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bl.ink', 's.id', 't.ly', 'lnkd.in',
]);

// TLDs muy usados en campañas de phishing por ser baratos o gratuitos.
// Plataformas de email marketing que reescriben los enlaces para medir clics.
export const TRACKING_DOMAINS = new Set([
  'sendgrid.net', 'list-manage.com', 'mailchimp.com', 'mcusercontent.com', 'mandrillapp.com',
  'hubspotlinks.com', 'hs-sites.com', 'hubspotemail.net', 'sparkpostmail.com', 'mailgun.org',
  'rs6.net', 'awstrack.me', 'exacttarget.com', 'mktomail.com', 'mailjet.com', 'sendibt2.com',
  'sendibt3.com', 'sendibm1.com', 'klclick.com', 'klaviyomail.com', 'createsend.com',
  'cmail19.com', 'cmail20.com', 'emltrk.com', 'mlsend.com', 'mailerlite.com', 'acems1.com',
]);

// Organizaciones que envían correo de millones de remitentes sin relación: su IP de entrada no es pista de campaña.
export const SHARED_MAIL_INFRA = new Set([
  'google.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'protection.outlook.com', 'microsoft.com',
  'amazonses.com', 'sendgrid.net', 'mailgun.org', 'mailgun.net', 'mcsv.net', 'mandrillapp.com',
  'sparkpostmail.com', 'yahoo.com', 'yahoodns.net', 'mailjet.com', 'zoho.com', 'zoho.eu', 'icloud.com',
  'me.com', 'apple.com', 'gmx.net', 'web.de', 'protonmail.ch', 'yandex.net', 'mailchimp.com', 'rsgsv.net',
  'messagelabs.com', 'pphosted.com', 'mimecast.com', 'ovh.net', 'ionos.com', 'secureserver.net',
]);

// Redes sociales y mensajería: aparecen en correos legítimos y fraudulentos sin que eso los relacione.
export const SOCIAL_DOMAINS = new Set([
  'x.com', 'twitter.com', 'facebook.com', 'fb.com', 'instagram.com', 'linkedin.com', 'youtube.com',
  'youtu.be', 'tiktok.com', 'wa.me', 'whatsapp.com', 't.me', 'telegram.me', 'pinterest.com', 'threads.net',
]);

// Plataformas de alojamiento donde cada cliente tiene su subdominio: la pista es el host completo.
export const HOSTING_PLATFORMS = new Set([
  'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'googleapis.com', 'appspot.com',
  'windows.net', 'azurewebsites.net', 'github.io', 'gitlab.io', 'netlify.app', 'vercel.app',
  'herokuapp.com', 'blogspot.com', 'wordpress.com', 'weebly.com', 'wixsite.com', 'glitch.me',
  'onrender.com', 'amazonaws.com', 'cloudfront.net', 'r2.dev', 'ngrok.io', 'ngrok-free.app',
]);

export const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'zip', 'mov', 'click', 'link', 'live', 'online', 'site', 'shop', 'icu',
  'buzz', 'rest', 'monster', 'cfd', 'sbs', 'gq', 'ml', 'cf', 'tk', 'ga', 'work', 'support',
  'cam', 'quest', 'fit', 'loan', 'win', 'bid', 'country', 'kim',
]);

export const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'msi', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'hta',
  'ps1', 'jar', 'lnk', 'iso', 'img', 'vhd', 'cab', 'dll', 'cpl', 'reg', 'html', 'htm', 'svg', 'one',
]);

export const MACRO_EXTENSIONS = new Set(['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'xlam', 'ppam']);

export const ARCHIVE_EXTENSIONS = new Set(['zip', 'rar', '7z', 'gz', 'tar']);

// Patrones de ingeniería social (es + en). Insensibles a mayúsculas.
export const LANGUAGE_PATTERNS = {
  credentials: {
    severity: 'high',
    title: 'Pide credenciales o datos bancarios',
    detail: 'Ninguna empresa legítima te pide la contraseña, el PIN o la tarjeta por email.',
    patterns: [
      /\b(verifi\w+|confirm\w+|actualic\w+|actualiz\w+|introduzc\w+|valid\w+)\b[^.\n]{0,40}\b(contraseña|clave|credenciales|pin|datos bancarios|tarjeta|cuenta)\b/i,
      /\b(verify|confirm|update|validate|enter)\b[^.\n]{0,40}\b(password|credentials|pin|card details|bank details|account|login)\b/i,
      /\b(número de tarjeta|código cvv|cvv|card number|social security)\b/i,
    ],
  },
  threat: {
    severity: 'medium',
    title: 'Amenaza con consecuencias',
    detail: 'Amenazar con bloquear, suspender o multar es una forma de que actúes sin pensar.',
    patterns: [
      /\b(será|serán|quedará|ha sido|será)\s+(suspendid\w+|bloquead\w+|cancelad\w+|cerrad\w+|eliminad\w+|desactivad\w+)/i,
      /\b(suspensión|bloqueo|cierre|cancelación) (de|definitiv\w+ de) (su|tu) cuenta\b/i,
      /\b(multa|sanción|acciones legales|recargo)\b/i,
      /\b(will be|has been)\s+(suspended|locked|closed|terminated|deleted|disabled)\b/i,
      /\b(legal action|penalty)\b/i,
    ],
  },
  urgency: {
    severity: 'medium',
    title: 'Mete prisa',
    detail: 'Los plazos muy cortos buscan que no te pares a comprobar si el mensaje es real.',
    patterns: [
      /\b(en (las próximas |un plazo de |menos de )?\d+\s*(horas|h|minutos)|inmediatamente|urgente|de inmediato|último aviso|hoy mismo|cuanto antes)\b/i,
      /\b(within \d+\s*(hours|h|minutes)|immediately|urgent|final notice|act now|as soon as possible)\b/i,
    ],
  },
  prize: {
    severity: 'medium',
    title: 'Promete un premio o reembolso',
    detail: 'Los premios inesperados y los reembolsos son ganchos clásicos del phishing.',
    patterns: [
      /\b(has ganado|ha ganado|ganador|premio|sorteo|reembolso|devolución de \d+|regalo gratis)\b/i,
      /\b(you('ve| have) won|winner|prize|lottery|refund|gift card)\b/i,
    ],
  },
};
