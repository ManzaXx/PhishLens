// Servidores cuyo Authentication-Results se acepta aunque no sean el receptor final
// (por ejemplo, Outlook añade la cabecera en un servidor interno con otro nombre).
// "*." = cualquier subdominio. Ampliable por el analista en el futuro (3.0).
export const TRUSTED_AUTHSERV = [
  'mx.google.com',
  '*.protection.outlook.com',
  '*.prod.outlook.com',
  'mx.zoho.eu',
  'mx.zoho.com',
  '*.yahoo.com',
  '*.icloud.com',
];
