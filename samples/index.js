// Emails de ejemplo. Todos son ficticios: los dominios de los "atacantes" usan el
// TLD reservado .test y no existen.
export const SAMPLES = [
  { id: '01-legitimo-newsletter', title: 'Newsletter legítima', file: '01-legitimo-newsletter.eml' },
  { id: '02-legitimo-pedido', title: 'Confirmación de pedido', file: '02-legitimo-pedido.eml' },
  { id: '03-phishing-banco', title: 'Phishing bancario', file: '03-phishing-banco.eml' },
  { id: '04-phishing-correos', title: 'Falso aviso de Correos', file: '04-phishing-correos.eml' },
  { id: '05-phishing-microsoft365', title: 'Falso Microsoft 365', file: '05-phishing-microsoft365.eml' },
  { id: '06-phishing-factura-adjunto', title: 'Factura con adjunto', file: '06-phishing-factura-adjunto.eml' },
  { id: '07-phishing-avanzado', title: 'Ataque avanzado', file: '07-phishing-avanzado.eml' },
  { id: '08-ruta-falsificada', title: 'Ruta falsificada', file: '08-ruta-falsificada.eml' },
  { id: '09-cabeceras-trampa', title: 'Cabeceras trampa', file: '09-cabeceras-trampa.eml' },
  { id: '10-dominio-unicode', title: 'Dominios con otros alfabetos', file: '10-dominio-unicode.eml' },
  // Adjuntos construidos byte a byte por tools/gen-samples.mjs: sin código ni malware.
  { id: '11-adjunto-tipo-falso', title: 'Adjunto con tipo falso', file: '11-adjunto-tipo-falso.eml' },
  { id: '12-pdf-activo-zip', title: 'PDF activo y ZIP cifrado', file: '12-pdf-activo-zip.eml' },
  { id: '13-redireccion-anidada', title: 'Redirección anidada', file: '13-redireccion-anidada.eml' },
];

// Lotes de ejemplo: varios correos que se analizan juntos (grafo y campañas).
export const BATCHES = [
  {
    id: 'lote-campana',
    title: 'Lote de campaña (4 correos)',
    files: [
      'lote-campana/1-entrega-fallida.eml', 'lote-campana/2-aviso-adjunto.eml',
      'lote-campana/3-aduana-retenido.eml', 'lote-campana/4-aduana-recordatorio.eml',
    ],
  },
];
