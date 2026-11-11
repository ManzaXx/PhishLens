// Emails de ejemplo (title en español, titleEn en inglés). Todos son ficticios: los dominios de los "atacantes" usan el
// TLD reservado .test y no existen.
export const SAMPLES = [
  { id: '01-legitimo-newsletter', title: 'Newsletter legítima', titleEn: 'Legitimate newsletter', file: '01-legitimo-newsletter.eml' },
  { id: '02-legitimo-pedido', title: 'Confirmación de pedido', titleEn: 'Order confirmation', file: '02-legitimo-pedido.eml' },
  { id: '03-phishing-banco', title: 'Phishing bancario', titleEn: 'Bank phishing', file: '03-phishing-banco.eml' },
  { id: '04-phishing-correos', title: 'Falso aviso de Correos', titleEn: 'Fake Correos notice', file: '04-phishing-correos.eml' },
  { id: '05-phishing-microsoft365', title: 'Falso Microsoft 365', titleEn: 'Fake Microsoft 365', file: '05-phishing-microsoft365.eml' },
  { id: '06-phishing-factura-adjunto', title: 'Factura con adjunto', titleEn: 'Invoice with attachment', file: '06-phishing-factura-adjunto.eml' },
  { id: '07-phishing-avanzado', title: 'Ataque avanzado', titleEn: 'Advanced attack', file: '07-phishing-avanzado.eml' },
  { id: '08-ruta-falsificada', title: 'Ruta falsificada', titleEn: 'Forged route', file: '08-ruta-falsificada.eml' },
  { id: '09-cabeceras-trampa', title: 'Cabeceras trampa', titleEn: 'Trap headers', file: '09-cabeceras-trampa.eml' },
  { id: '10-dominio-unicode', title: 'Dominios con otros alfabetos', titleEn: 'Domains in other alphabets', file: '10-dominio-unicode.eml' },
  // Adjuntos construidos byte a byte por tools/gen-samples.mjs: sin código ni malware.
  { id: '11-adjunto-tipo-falso', title: 'Adjunto con tipo falso', titleEn: 'Attachment with a fake type', file: '11-adjunto-tipo-falso.eml' },
  { id: '12-pdf-activo-zip', title: 'PDF activo y ZIP cifrado', titleEn: 'Active PDF and encrypted ZIP', file: '12-pdf-activo-zip.eml' },
  { id: '13-redireccion-anidada', title: 'Redirección anidada', titleEn: 'Nested redirect', file: '13-redireccion-anidada.eml' },
];

// Lotes de ejemplo: varios correos que se analizan juntos (grafo y campañas).
export const BATCHES = [
  {
    id: 'lote-campana',
    title: 'Lote de campaña (4 correos)',
    titleEn: 'Campaign batch (4 emails)',
    files: [
      'lote-campana/1-entrega-fallida.eml', 'lote-campana/2-aviso-adjunto.eml',
      'lote-campana/3-aduana-retenido.eml', 'lote-campana/4-aduana-recordatorio.eml',
    ],
  },
];
