// Panel «Vista segura»: el mensaje como texto plano, sin nada activo.
import { el } from '../dom.js';
import { highlight } from '../highlight.js';
import { htmlToText } from '../../parser/html.js';
import { reveal } from '../../lib/text.js';
import { t } from '../../i18n/index.js';


export function safeViewPanel(report) {
  const text = report.email.text?.trim() ? report.email.text : htmlToText(report.email.html ?? '');
  const panel = el('div');
  if (!text.trim()) {
    panel.append(el('p', { className: 'empty empty--muted', text: t('safe.none') }));
    return panel;
  }
  panel.append(el('p', { className: 'hint', text: t('safe.hint') }));
  const box = el('div', { className: 'safe-view', attrs: { tabindex: '0', 'aria-label': t('safe.label') } });
  for (const part of highlight(text)) {
    box.append(part.kind
      ? el('mark', { className: `hl hl--${part.kind}`, text: part.text, attrs: { title: part.kind === 'url' ? t('safe.mark.url') : t('safe.mark.phrase') } })
      : document.createTextNode(reveal(part.text)));
  }
  panel.append(box);

  const links = report.email.links ?? [];
  if (links.length) {
    const list = el('ul', { className: 'linklist' });
    for (const link of links.slice(0, 30)) {
      const item = el('li', {}, el('span', { text: link.text || t('safe.noText') }));
      if (link.text !== link.href) item.append(el('span', { className: 'mono', text: `→ ${link.href}` }));
      list.append(item);
    }
    panel.append(el('section', { className: 'safe-links' },
      el('h4', { className: 'group__title', text: t('safe.links', { n: links.length }) }), list));
  }
  return panel;
}
