import { el } from '../dom.js';

/** Pasos numerados (qué hacer ahora). */
export function stepList(steps) {
  return el('ol', { className: 'steps' }, ...steps.map((s) => el('li', { className: 'steps__item', text: s })));
}
