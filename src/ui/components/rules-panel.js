// Panel «Reglas propias» de la portada (spec 3.0, §5.2): vacío, errores, vista previa o activas.
// Todo lo que viene del fichero de reglas va con textContent (el() revela los caracteres de dirección).
import { el } from '../dom.js';
import { dataTable } from './data-table.js';
import { severityTag } from './severity-tag.js';

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

function previewText(p) {
  if (!p.testable) return 'No se puede probar: el historial no guarda el correo';
  if (!p.total) return 'Sin análisis guardados para probarla';
  return `Cumpliría en ${p.matches} de ${p.total} análisis guardados`;
}

function table(rules, preview) {
  const byId = new Map(preview.map((p) => [p.id, p]));
  return dataTable({
    caption: 'Reglas del fichero',
    columns: ['Regla', 'Gravedad', 'Con el historial'],
    rows: rules.map((r) => [
      el('span', {}, el('strong', { text: r.title }), el('span', { className: 'rules__id mono', text: r.id })),
      severityTag(r.severity),
      byId.has(r.id) ? previewText(byId.get(r.id)) : '—',
    ]),
  });
}

const button = (text, action, cls = 'btn') => el('button', { className: cls, text, attrs: { type: 'button', 'data-action': action } });

/** @param {{state: 'empty'|'errors'|'preview'|'active', errors?: string[], preview?, rules?}} model (errors ya en texto, con formatRuleError) */
export function rulesPanel({ state, errors = [], preview = [], rules = [] }) {
  const box = el('div', { className: 'rules__panel', attrs: { 'data-state': state } });
  if (state === 'errors') {
    box.append(el('div', { className: 'rules__errors', attrs: { role: 'alert', tabindex: '-1' } },
      el('p', { className: 'rules__summary', text: `No se han cargado las reglas: el fichero tiene ${plural(errors.length, 'error', 'errores')}.` }),
      el('ul', {}, ...errors.map((e) => el('li', { className: 'mono', text: String(e) })))));
    return box;
  }
  if (state === 'preview') {
    box.append(
      el('p', { className: 'rules__summary', text: `${plural(rules.length, 'regla válida', 'reglas válidas')}. Revisa la vista previa antes de activarlas.`, attrs: { tabindex: '-1' } }),
      table(rules, preview),
      el('div', { className: 'rules__actions' }, button('Activar reglas', 'rules-activate', 'btn btn--primary'), button('Descartar', 'rules-discard')));
    return box;
  }
  if (state === 'active') {
    box.append(
      el('p', { className: 'rules__summary', text: plural(rules.length, 'regla activa', 'reglas activas'), attrs: { tabindex: '-1' } }),
      table(rules, preview),
      el('div', { className: 'rules__actions' }, button('Quitar reglas', 'rules-remove')));
    return box;
  }
  box.append(el('p', { className: 'muted rules__summary', text: 'No hay reglas propias cargadas.' }));
  return box;
}
