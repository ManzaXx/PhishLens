// Límites defensivos frente a emails construidos para agotar CPU o memoria.
// Todos en un sitio para poder auditarlos y probarlos juntos.
export const LIMITS = {
  depth: 20,
  parts: 500,
  links: 200,
  attachments: 100,
  attachmentBytes: 10 * 1024 * 1024,
  rawBytes: 25 * 1024 * 1024,
};
