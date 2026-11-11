import { el } from '../dom.js';
import { t } from '../../i18n/index.js';

/** Conmutador «Sencillo» / «Modo analista» (dos botones con aria-pressed). */
export function modeSwitch(mode) {
  const analyst = mode === 'analyst';
  const button = (text, action, pressed) => el('button', {
    className: 'mode-switch__btn', text, attrs: { type: 'button', 'data-action': action, 'aria-pressed': String(pressed) },
  });
  return el('div', { className: 'mode-switch', attrs: { role: 'group', 'aria-label': t('report.mode.group') } },
    button(t('report.mode.simple'), 'mode-simple', !analyst),
    button(t('report.mode.analyst'), 'mode-analyst', analyst));
}
