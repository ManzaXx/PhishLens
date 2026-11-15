import { el, nextId } from '../dom.js';
import { severityKey, severityLabel } from './labels.js';
import { t } from '../../i18n/index.js';

/**
 * Fila del modo sencillo: la señal en lenguaje llano y su gravedad en texto (el punto de color solo acompaña).
 * Con `index` (posición del hallazgo en report.findings) añade «Ver la prueba», que abre esa señal en el modo
 * analista (auditoría 3.1, P9). El botón se describe con el texto de la señal (aria-describedby), no con un
 * aria-label armado con texto del correo.
 */
export function signalRow(f, { index } = {}) {
  const key = severityKey(f.severity);
  const linked = Number.isInteger(index) && index >= 0;
  const textId = linked ? nextId('signal') : null;
  return el('li', { className: `signal sev-${key}` },
    el('span', { className: 'signal__dot', attrs: { 'aria-hidden': 'true' } }),
    el('span', { className: 'signal__text', text: f.plain || f.title, attrs: textId ? { id: textId } : {} }),
    el('span', { className: 'signal__sev', text: severityLabel(key) }),
    linked ? el('button', {
      className: 'btn btn--small signal__link',
      text: t('simple.evidence'),
      attrs: { type: 'button', 'data-action': 'show-finding', 'data-index': String(index), 'aria-describedby': textId },
    }) : null);
}
