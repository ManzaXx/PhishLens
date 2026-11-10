// Diálogo del informe forense: notas del analista (texto libre, nunca se interpreta) y las dos salidas.
import { el, nextId } from '../dom.js';

const MAX = 5000;
// En es-ES, toLocaleString no agrupa los números de 4 cifras: el punto se pone a mano.
const fmt = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, '.');
/** «N de 5.000». */
export const notesCount = (n) => `${fmt(n)} de ${fmt(MAX)}`;
const button = (text, action, className = 'btn') => el('button', { className, text, attrs: { type: 'button', 'data-action': action } });

export function forensicDialog({ notes = '' } = {}) {
  const title = nextId('forensic-title');
  const field = nextId('forensic-notes');
  const hint = nextId('forensic-hint');
  const value = String(notes).slice(0, MAX);
  return el('dialog', { className: 'forensic-dialog', attrs: { 'aria-labelledby': title } },
    el('h2', { className: 'forensic-dialog__title', text: 'Informe forense', attrs: { id: title } }),
    el('p', { className: 'muted', text: 'Lleva los hashes del correo, el veredicto, las señales, la autenticación, la ruta, los IOCs, los adjuntos y las URLs.' }),
    el('label', { className: 'forensic-dialog__label', text: 'Notas del analista (opcional)', attrs: { for: field } }),
    el('textarea', { className: 'forensic-dialog__notes', text: value, attrs: { id: field, rows: '6', maxlength: String(MAX), 'data-role': 'forensic-notes', 'aria-describedby': hint } }),
    el('p', { className: 'muted forensic-dialog__count', text: notesCount(value.length), attrs: { 'data-role': 'forensic-count', 'aria-live': 'polite' } }),
    el('p', { className: 'muted', text: 'Si el historial está activado, las notas se guardan con este análisis.', attrs: { id: hint } }),
    el('div', { className: 'forensic-dialog__actions' },
      button('Guardar como PDF', 'forensic-print', 'btn btn--primary'),
      button('Descargar JSON', 'forensic-json'),
      button('Cerrar', 'forensic-close')),
    el('p', { className: 'muted', text: 'En el diálogo de impresión, elige «Guardar como PDF» como destino.' }));
}
