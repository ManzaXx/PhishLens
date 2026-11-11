// Panel «Reglas propias» de la portada (spec 3.0, §5.2): vacío, errores, vista previa o activas.
// Todo lo que viene del fichero de reglas va con textContent (el() revela los caracteres de dirección).
import { el } from '../dom.js';
import { dataTable } from './data-table.js';
import { severityTag } from './severity-tag.js';
import { t } from '../../i18n/index.js';

function previewText(p) {
  if (!p.testable) return t('rules.preview.untestable');
  if (!p.total) return t('rules.preview.empty');
  return t('rules.preview.matches', { matches: p.matches, total: p.total });
}

function table(rules, preview) {
  const byId = new Map(preview.map((p) => [p.id, p]));
  return dataTable({
    caption: t('rules.table.caption'),
    columns: [t('rules.table.rule'), t('rules.table.severity'), t('rules.table.history')],
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
      el('p', { className: 'rules__summary', text: t('rules.errors.summary', { count: errors.length }) }),
      el('ul', {}, ...errors.map((e) => el('li', { className: 'mono', text: String(e) })))));
    return box;
  }
  if (state === 'preview') {
    box.append(
      el('p', { className: 'rules__summary', text: t('rules.preview.summary', { count: rules.length }), attrs: { tabindex: '-1' } }),
      table(rules, preview),
      el('div', { className: 'rules__actions' }, button(t('rules.activate'), 'rules-activate', 'btn btn--primary'), button(t('rules.discard'), 'rules-discard')));
    return box;
  }
  if (state === 'active') {
    box.append(
      el('p', { className: 'rules__summary', text: t('rules.active.summary', { count: rules.length }), attrs: { tabindex: '-1' } }),
      table(rules, preview),
      el('div', { className: 'rules__actions' }, button(t('rules.remove'), 'rules-remove')));
    return box;
  }
  box.append(el('p', { className: 'muted rules__summary', text: t('rules.none') }));
  return box;
}
