import { el } from '../dom.js';

/** Conmutador «Sencillo» / «Modo analista» (dos botones con aria-pressed). */
export function modeSwitch(mode) {
  const analyst = mode === 'analyst';
  const button = (text, action, pressed) => el('button', {
    className: 'mode-switch__btn', text, attrs: { type: 'button', 'data-action': action, 'aria-pressed': String(pressed) },
  });
  return el('div', { className: 'mode-switch', attrs: { role: 'group', 'aria-label': 'Nivel de detalle' } },
    button('Sencillo', 'mode-simple', !analyst),
    button('Modo analista', 'mode-analyst', analyst));
}
