// Diálogo del informe forense: notas del analista (texto libre, nunca se interpreta) y las dos salidas.
import { el, nextId } from '../dom.js';
import { t, fmtNumber } from '../../i18n/index.js';

const MAX = 5000;
/** «N de 5.000». */
export const notesCount = (n) => t('forensic.count', { n: fmtNumber(n), max: fmtNumber(MAX) });
const button = (text, action, className = 'btn') => el('button', { className, text, attrs: { type: 'button', 'data-action': action } });

/** Aviso cuando el historial está activado y las notas no se han guardado; null si no hay nada que decir. */
export function notesSaveMessage({ enabled, ok }) {
  return enabled && !ok ? t('forensic.notes.unsaved') : null;
}

// value y no textContent: las notas vuelven tal cual (sin revelar los caracteres de dirección) y un
// textarea nunca interpreta su valor como HTML.
function notesField(value, opts) {
  const ta = el('textarea', opts);
  ta.value = value;
  return ta;
}

export function forensicDialog({ notes = '' } = {}) {
  const title = nextId('forensic-title');
  const field = nextId('forensic-notes');
  const hint = nextId('forensic-hint');
  const value = String(notes).slice(0, MAX);
  return el('dialog', { className: 'forensic-dialog', attrs: { 'aria-labelledby': title } },
    el('h2', { className: 'forensic-dialog__title', text: t('forensic.title'), attrs: { id: title } }),
    el('p', { className: 'muted', text: t('forensic.contents') }),
    el('label', { className: 'forensic-dialog__label', text: t('forensic.notes.label'), attrs: { for: field } }),
    notesField(value, { className: 'forensic-dialog__notes', attrs: { id: field, rows: '6', maxlength: String(MAX), 'data-role': 'forensic-notes', 'aria-describedby': hint } }),
    el('p', { className: 'muted forensic-dialog__count', text: notesCount(value.length), attrs: { 'data-role': 'forensic-count', 'aria-live': 'polite' } }),
    el('p', { className: 'muted', text: t('forensic.notes.hint'), attrs: { id: hint } }),
    el('div', { className: 'forensic-dialog__actions' },
      button(t('forensic.print'), 'forensic-print', 'btn btn--primary'),
      button(t('forensic.json'), 'forensic-json'),
      button(t('common.close'), 'forensic-close')),
    el('p', { className: 'muted', text: t('forensic.print.hint') }));
}
