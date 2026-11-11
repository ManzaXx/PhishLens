import { el } from '../dom.js';
import { t } from '../../i18n/index.js';

/**
 * Navegación del modo analista: un grupo con título por bloque y un enlace por vista.
 * groups: [{label, views: [{id, label}]}]; counts: {vista: número}.
 */
export function navRail({ groups, current, counts = {} }) {
  const nav = el('nav', { className: 'nav-rail', attrs: { 'aria-label': t('nav.label') } });
  for (const group of groups) {
    if (!group.views.length) continue;
    const list = el('ul', { className: 'nav-rail__list' });
    for (const view of group.views) {
      const count = Object.hasOwn(counts, view.id) ? counts[view.id] : null;
      const attrs = { href: `#analista/${view.id}` };
      if (view.id === current) attrs['aria-current'] = 'page';
      list.append(el('li', {}, el('a', { className: 'nav-rail__link', attrs },
        el('span', { text: view.label }),
        count != null ? el('span', { className: 'nav-rail__count', text: String(count) }) : null)));
    }
    // Un grupo de una sola vista con su mismo nombre no repite el título.
    const alone = group.views.length === 1 && group.views[0].label === group.label;
    nav.append(el('div', { className: 'nav-rail__group' }, alone ? null : el('h3', { className: 'nav-rail__title', text: group.label }), list));
  }
  return nav;
}
