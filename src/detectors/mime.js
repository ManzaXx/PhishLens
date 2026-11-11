// Ambigüedades MIME (spec 2.2, §8.3): correos que dos programas leerían distinto. El parser
// decide una interpretación y la anota en parseNotes; este detector la convierte en hallazgo
// para que no pase en silencio.
import { finding } from '../core/finding.js';

export const name = 'mime';

const RULES = {
  'mime.duplicate-content-type': { id: 'mime.duplicate-content-type', severity: 'medium', title: 'Content-Type repetido' },
  'mime.boundary-reuse': { id: 'mime.boundary-reuse', severity: 'medium', title: 'El mismo separador MIME en dos niveles' },
  'mime.boundary-in-content': { id: 'mime.boundary-in-content', severity: 'low', title: 'Separador MIME en mitad del texto' },
  'mime.unterminated-multipart': { id: 'mime.unclosed-multipart', severity: 'low', title: 'Partes MIME sin cerrar' },
  'mime.charset-conflict': { id: 'mime.charset-conflict', severity: 'low', title: 'Codificación de caracteres contradictoria' },
  'mime.header-without-colon': { id: 'mime.header-without-colon', severity: 'low', title: 'Línea de cabecera sin «:»' },
  'mime.nested-message': { id: 'mime.nested-message', severity: 'low', title: 'Correo dentro de otro correo' },
};

export function detect(email) {
  const notes = email.parseNotes ?? [];
  const out = [];
  for (const n of notes) {
    const rule = Object.hasOwn(RULES, n.code) ? RULES[n.code] : null;
    if (rule) out.push(finding({ ...rule, detector: name, detail: n.detail, evidence: n.code, params: { ...n.params } }));
  }
  const limits = notes.filter((n) => n.code.startsWith('limit.'));
  if (limits.length) {
    out.push(finding({
      id: 'mime.limit', detector: name, severity: 'info',
      title: 'Parte del correo no se ha analizado',
      detail: limits.map((n) => n.detail).join(' '),
      params: { notes: limits.map((n) => ({ code: `rule.note.${n.code}`, params: n.params ?? {} })) },
      evidence: limits.map((n) => n.code).join(', '),
    }));
  }
  return out;
}
