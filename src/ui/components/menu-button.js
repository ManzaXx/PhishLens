import { el, icon, nextId } from '../dom.js';

/**
 * Botón con menú (patrón ARIA «menu button»). El comportamiento (abrir, flechas, Escape, clic fuera)
 * lo pone app.js con menuKey(); aquí solo la estructura.
 */
export function menuButton({ label, items }) {
  const buttonId = nextId('menu-btn');
  const menuId = nextId('menu');
  const button = el('button', {
    className: 'btn menu-button__trigger',
    attrs: { type: 'button', id: buttonId, 'aria-haspopup': 'menu', 'aria-expanded': 'false', 'aria-controls': menuId },
  }, el('span', { text: label }), icon('chevron'));
  const menu = el('ul', { className: 'menu-button__menu', attrs: { role: 'menu', id: menuId, 'aria-labelledby': buttonId } },
    ...items.map((item) => el('li', { attrs: { role: 'none' } },
      el('button', { className: 'menu-button__item', text: item.text, attrs: { type: 'button', role: 'menuitem', tabindex: '-1', 'data-action': item.action } }))));
  menu.hidden = true;
  return el('div', { className: 'menu-button' }, button, menu);
}

/**
 * Tecla dentro del menú → {index, close}, o null si la tecla no es del menú.
 * Flechas circulares, Inicio y Fin; Escape y Tab cierran.
 */
export function menuKey(index, key, count) {
  if (key === 'Escape' || key === 'Tab') return { index, close: true };
  const next = { ArrowDown: index + 1, ArrowUp: index - 1, Home: 0, End: count - 1 }[key];
  if (next === undefined) return null;
  return { index: ((next % count) + count) % count, close: false };
}
