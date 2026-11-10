// Límites defensivos frente a emails construidos para agotar CPU o memoria.
// Todos en un sitio para poder auditarlos y probarlos juntos.
export const LIMITS = {
  depth: 20,
  parts: 500,
  links: 200,
  attachments: 100,
  attachmentBytes: 10 * 1024 * 1024,
  rawBytes: 25 * 1024 * 1024,
  inputBytes: 25 * 1024 * 1024,
  headers: 1000,
  headerBytes: 64 * 1024,
  batchFiles: 50,
  batchBytes: 100 * 1024 * 1024,
  // Texto del cuerpo que miran las reglas propias (body.text): 2.000 condiciones sobre 25 MB bloquearían la pestaña.
  ruleBodyChars: 256 * 1024,
};
