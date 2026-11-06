import { el } from '../dom.js';

/** Estado vacío: título y una frase que dice qué hacer. */
export function emptyState(title, text) {
  return el('div', { className: 'empty-state' },
    el('p', { className: 'empty-state__title', text: title }),
    text ? el('p', { className: 'empty-state__text', text }) : null);
}
