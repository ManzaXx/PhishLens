// Panel «Vista segura»: el mensaje como texto plano, sin nada activo.
import { el } from '../dom.js';
import { highlight } from '../highlight.js';
import { htmlToText } from '../../parser/html.js';
import { reveal } from '../../lib/text.js';


export function safeViewPanel(report) {
  const text = report.email.text?.trim() ? report.email.text : htmlToText(report.email.html ?? '');
  const panel = el('div');
  if (!text.trim()) {
    panel.append(el('p', { className: 'empty empty--muted', text: 'No hay texto que mostrar.' }));
    return panel;
  }
  panel.append(el('p', { className: 'hint', text: 'El mensaje como texto plano: sin imágenes, sin enlaces activos y con las frases sospechosas resaltadas.' }));
  const box = el('div', { className: 'safe-view', attrs: { tabindex: '0', 'aria-label': 'Texto del email' } });
  for (const part of highlight(text)) {
    box.append(part.kind
      ? el('mark', { className: `hl hl--${part.kind}`, text: part.text, attrs: { title: part.kind === 'url' ? 'Enlace (desactivado)' : 'Frase de ingeniería social' } })
      : document.createTextNode(reveal(part.text)));
  }
  panel.append(box);

  const links = report.email.links ?? [];
  if (links.length) {
    const list = el('ul', { className: 'linklist' });
    for (const link of links.slice(0, 30)) {
      const item = el('li', {}, el('span', { text: link.text || '(sin texto)' }));
      if (link.text !== link.href) item.append(el('span', { className: 'mono', text: `→ ${link.href}` }));
      list.append(item);
    }
    panel.append(el('section', { className: 'safe-links' },
      el('h4', { className: 'group__title', text: `Enlaces: lo que se ve → a dónde llevan (${links.length})` }), list));
  }
  return panel;
}
