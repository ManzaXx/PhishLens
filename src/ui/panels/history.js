// Vista «Historial» (spec 3.0, §2.3). Recibe los datos ya leídos del historial (app.js hace las llamadas
// asíncronas) y solo pinta: texto con textContent, IOCs y remitentes defanged, acciones por data-action.
import { el, nextId } from '../dom.js';
import { defang } from '../../intel/ioc.js';
import { LEVELS } from '../../core/scoring.js';
import { emptyState } from '../components/empty-state.js';
import { dataTable } from '../components/data-table.js';
import { t, fmtDate } from '../../i18n/index.js';

const ranges = () => [['', t('history.range.all')], ['7', t('history.range.7')], ['30', t('history.range.30')]];
const TYPES = new Set(['domains', 'ips', 'urls', 'emails', 'hashes', 'sha1', 'md5']);
const typeLabel = (type) => (TYPES.has(type) ? t(`ioc.type.${type}`) : type);

const button = (text, action, extra = {}, className = 'btn') => el('button', { className, text, attrs: { type: 'button', 'data-action': action, ...extra } });
const when = (iso) => fmtDate(new Date(iso), { dateStyle: 'short', timeStyle: 'short' });
const levelLabel = (level) => (LEVELS.some((l) => l.level === level) ? t(`level.${level}`) : level);

function field(label, control) {
  const id = nextId('history-field');
  control.setAttribute('id', id);
  return el('div', { className: 'history__field' }, el('label', { text: label, attrs: { for: id } }), control);
}

function select(action, name, options, value = '') {
  const s = el('select', { attrs: { 'data-action': action, 'data-filter': name } });
  for (const [v, label] of options) {
    const o = el('option', { text: label, attrs: { value: v } });
    if (v === String(value ?? '')) o.setAttribute('selected', '');
    s.append(o);
  }
  return s;
}

function searchBox(search) {
  const input = el('input', { attrs: { type: 'search', 'data-role': 'history-query', autocomplete: 'off', spellcheck: 'false', value: search?.query ?? '' } });
  const form = el('div', { className: 'history__search' }, field(t('history.search.label'), input), button(t('history.search'), 'history-search'));
  if (!search) return form;
  const results = search.results ?? [];
  const list = results.length
    ? el('ul', { className: 'history__hits' }, ...results.map((h) => el('li', {},
      el('span', { className: 'history__ioc', text: defang(h.value) }),
      el('span', { className: 'hint', text: ` · ${typeLabel(h.type)} · ${t('history.search.hits', { count: h.ids.length })}` }))))
    : el('p', { className: 'hint', text: String(search.query ?? '').trim().length < 3 ? t('history.search.short') : t('history.search.none') });
  return el('div', {}, form, list);
}

function filters(current, techniques) {
  return el('div', { className: 'history__filters' },
    field(t('history.filter.level'), select('history-filter', 'level', [['', t('history.filter.allLevels')], ...LEVELS.map((l) => [l.level, t(`level.${l.level}`)])], current.level)),
    field(t('history.filter.date'), select('history-filter', 'range', ranges(), current.range)),
    field(t('history.filter.technique'), select('history-filter', 'technique', [['', t('history.filter.allTechniques')], ...techniques.map((tech) => [tech, tech])], current.technique)));
}

function table(items, selected) {
  const rows = items.map((e) => {
    const box = el('input', { attrs: { type: 'checkbox', 'data-action': 'history-select', 'data-id': e.id, 'aria-label': t('history.compare.one', { name: e.name ?? t('history.thisAnalysis') }) } });
    if (selected.includes(e.id)) box.setAttribute('checked', '');
    return [
      when(e.savedAt),
      defang(e.report.email?.from?.address ?? '—'),
      el('span', { className: 'history__subject' }, e.report.email?.subject ?? '—',
        e.name ? el('span', { className: 'history__name', text: e.name }) : null),
      el('span', { className: `level-tag level-tag--${e.report.level}`, text: levelLabel(e.report.level) }),
      el('span', { className: 'history__row-actions' },
        button(t('history.open'), 'history-open', { 'data-id': e.id }),
        button(t('history.delete'), 'history-delete', { 'data-id': e.id, 'aria-label': t('history.delete.one', { name: e.name ?? t('history.thisAnalysis') }) }),
        el('label', { className: 'history__compare-pick' }, box, el('span', { text: t('history.compare'), attrs: { 'aria-hidden': 'true' } }))),
    ];
  });
  return dataTable({ caption: t('history.table.caption'), columns: [t('history.col.date'), t('history.col.sender'), t('history.col.subject'), t('history.col.level'), t('history.col.actions')], rows, className: 'history__table' });
}

function pager({ offset = 0, total, items }) {
  const from = total ? offset + 1 : 0;
  const to = offset + items.length;
  return el('div', { className: 'history__pager' },
    offset > 0 ? button(t('history.prev'), 'history-page', { 'data-offset': String(Math.max(0, offset - 50)) }) : null,
    el('p', { className: 'hint', text: t('history.range', { from, to, total }) }),
    to < total ? button(t('history.next'), 'history-page', { 'data-offset': String(to) }) : null);
}

function comparison(c) {
  const delta = c.scoreDelta;
  const sign = delta > 0 ? '+' : delta < 0 ? '−' : '±';
  const listOf = (title, values, fmt = (v) => v) => el('div', {}, el('h4', { text: title }),
    values.length ? el('ul', {}, ...values.map((v) => el('li', { text: fmt(v) }))) : el('p', { className: 'hint', text: t('history.compare.none') }));
  return el('section', { className: 'card history__compare', attrs: { 'aria-label': t('history.comparison') } },
    el('h3', { text: t('history.compare.title', { a: c.a.name ?? 'A', b: c.b.name ?? 'B' }) }),
    el('p', { text: t('history.compare.delta', { delta: `${sign}${Math.abs(delta)}` }) }),
    el('div', { className: 'history__compare-grid' },
      listOf(t('history.compare.sharedIocs'), c.sharedIocs, defang),
      listOf(t('history.compare.onlyIn', { name: c.a.name ?? 'A' }), c.onlyA, defang),
      listOf(t('history.compare.onlyIn', { name: c.b.name ?? 'B' }), c.onlyB, defang),
      listOf(t('history.compare.sharedSignals'), c.findings.shared),
      listOf(t('history.compare.signalsOnlyIn', { name: c.a.name ?? 'A' }), c.findings.onlyA),
      listOf(t('history.compare.signalsOnlyIn', { name: c.b.name ?? 'B' }), c.findings.onlyB)));
}

function importSummary(res) {
  if (!res) return null;
  return el('div', { className: 'history__import', attrs: { role: 'status' } },
    el('p', { text: t('history.import.result', { imported: res.imported, rejected: res.rejected.length }) }),
    res.rejected.length ? el('ul', {}, ...res.rejected.map((r) => el('li', { text: r.index < 0 ? r.error : t('history.import.entry', { n: r.index + 1, error: r.error }) }))) : null);
}

function clearDialog(total) {
  const title = nextId('history-dialog');
  return el('dialog', { className: 'history__dialog', attrs: { 'aria-labelledby': title } },
    el('p', { text: t('history.clear.question', { count: total }), attrs: { id: title } }),
    el('div', { className: 'history__dialog-actions' },
      button(t('history.clear.cancel'), 'history-clear-cancel'),
      button(t('history.clear.confirm', { count: total }), 'history-clear-confirm', {}, 'btn btn--danger')));
}

/** options.history: {page: {items, total, skipped, offset}, filters, techniques, search, compare, selected, importResult}. */
export function historyPanel(_report, options = {}) {
  const h = options.history ?? {};
  const page = h.page ?? { items: [], total: 0, skipped: 0, offset: 0 };
  // Lo que se borra y si hay algo guardado se cuenta sin filtros; page.total es lo que cumple los filtros.
  const totalAll = h.totalAll ?? page.total;
  const tools = el('div', { className: 'history__tools' },
    button(t('history.export'), 'history-export'),
    button(t('history.import'), 'history-import'),
    totalAll ? button(t('history.clear'), 'history-clear') : null);
  const parts = [
    el('p', { className: 'hint', text: t('history.hint') }),
    tools,
    importSummary(h.importResult),
  ];
  if (!totalAll && !page.skipped && !h.search) {
    parts.push(emptyState(t('history.empty.title'), t('history.empty.text')));
    return el('div', { className: 'stack history' }, ...parts);
  }
  parts.push(searchBox(h.search), filters(h.filters ?? {}, h.techniques ?? []));
  if (page.skipped) parts.push(el('p', { className: 'graph__note', text: t('history.skipped', { count: page.skipped }) }));
  if (page.items.length) parts.push(table(page.items, h.selected ?? []), pager(page));
  else parts.push(el('p', { className: 'hint', text: t('history.filter.none') }));
  if ((h.selected ?? []).length === 2) parts.push(button(t('history.compare.two'), 'history-compare'));
  else parts.push(el('p', { className: 'hint', text: t('history.compare.pick') }));
  if (h.compare) parts.push(comparison(h.compare));
  parts.push(clearDialog(totalAll));
  return el('div', { className: 'stack history' }, ...parts);
}
