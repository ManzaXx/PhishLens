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

// Rangos internos de proveedores grandes: un salto cuyo emisor dice ser del proveedor (HELO) y cuya
// IP, anotada por el propio receptor, cae aquí es un salto entre sus servidores. Exchange Online usa
// 2603:10a6::/32 (Europa) y 2603:10b6::/32 (América) para el tráfico interno entre sus buzones; las
// máquinas virtuales de Azure salen por otros rangos, así que un atacante no puede originar desde aquí.
export const INTERNAL_RELAYS = [
  { org: 'outlook.com', cidrs: [['2603:10a6::', 32], ['2603:10b6::', 32]] },
];
