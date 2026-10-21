// Detector de adjuntos peligrosos. Solo mira el nombre y el tipo: nunca abre el contenido.
import { finding } from './finding.js';
import { DANGEROUS_EXTENSIONS, MACRO_EXTENSIONS, ARCHIVE_EXTENSIONS } from '../data/lists.js';

export const name = 'attachments';

const DOCUMENT_LIKE = /^(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|csv|rtf|odt)$/;

export function detect(email) {
  const out = [];
  for (const { filename } of email.attachments ?? []) {
    if (/[\u202A-\u202E\u2066-\u2069]/.test(filename)) {
      out.push(finding({
        id: 'attachments.rtl-override',
        detector: name,
        severity: 'high',
        title: 'Nombre de adjunto invertido',
        detail: 'El nombre contiene un carácter que invierte el sentido del texto: "factura\u202Efdp.exe" se ve como "facturaexe.pdf".',
        evidence: filename.replace(/[\u202A-\u202E\u2066-\u2069]/g, '⟦RLO⟧'),
      }));
      continue;
    }
    const parts = String(filename).toLowerCase().split('.').map((p) => p.trim());
    if (parts.length < 2) continue;
    const ext = parts.at(-1);
    const prev = parts.length > 2 ? parts.at(-2) : null;

    if (DANGEROUS_EXTENSIONS.has(ext) && prev && DOCUMENT_LIKE.test(prev)) {
      out.push(finding({
        id: 'attachments.double-extension',
        detector: name,
        severity: 'high',
        title: 'Adjunto con doble extensión',
        detail: `"${filename}" parece un .${prev} pero en realidad es un .${ext}. Es un truco clásico para colar malware.`,
        evidence: filename,
      }));
    } else if (DANGEROUS_EXTENSIONS.has(ext)) {
      out.push(finding({
        id: 'attachments.dangerous',
        detector: name,
        severity: 'high',
        title: 'Adjunto que puede ejecutar código',
        detail: `Los ficheros .${ext} pueden ejecutar programas en tu ordenador al abrirlos.`,
        evidence: filename,
      }));
    } else if (MACRO_EXTENSIONS.has(ext)) {
      out.push(finding({
        id: 'attachments.macro',
        detector: name,
        severity: 'medium',
        title: 'Documento con macros',
        detail: `Los .${ext} pueden contener macros, una vía habitual de infección.`,
        evidence: filename,
      }));
    } else if (ARCHIVE_EXTENSIONS.has(ext)) {
      out.push(finding({
        id: 'attachments.archive',
        detector: name,
        severity: 'low',
        title: 'Fichero comprimido',
        detail: 'Los comprimidos se usan para esconder ejecutables de los filtros antivirus del correo.',
        evidence: filename,
      }));
    }
  }
  return out;
}
