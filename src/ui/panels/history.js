// Vista «Historial» (spec 3.0, §2.3). Recibe los datos ya leídos del historial (app.js hace las llamadas
// asíncronas) y solo pinta: texto con textContent, IOCs y remitentes defanged, acciones por data-action.
import { el, nextId } from '../dom.js';
import { defang } from '../../intel/ioc.js';
import { LEVELS } from '../../core/scoring.js';
import { emptyState } from '../components/empty-state.js';
import { dataTable } from '../components/data-table.js';

const RANGES = [['', 'Todo'], ['7', 'Últimos 7 días'], ['30', 'Últimos 30 días']];
const TYPES = { domains: 'Dominio', ips: 'IP', urls: 'URL', emails: 'Dirección', hashes: 'SHA-256', sha1: 'SHA-1', md5: 'MD5' };

const button = (text, action, extra = {}, className = 'btn') => el('button', { className, text, attrs: { type: 'button', 'data-action': action, ...extra } });
const when = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' });
};
const levelLabel = (level) => LEVELS.find((l) => l.level === level)?.label ?? level;

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
  const form = el('div', { className: 'history__search' }, field('Buscar un IOC (dominio, IP, URL, dirección o hash)', input), button('Buscar', 'history-search'));
  if (!search) return form;
  const results = search.results ?? [];
  const list = results.length
    ? el('ul', { className: 'history__hits' }, ...results.map((h) => el('li', {},
      el('span', { className: 'history__ioc', text: defang(h.value) }),
      el('span', { className: 'hint', text: ` · ${TYPES[h.type] ?? h.type} · aparece en ${h.ids.length} ${h.ids.length === 1 ? 'análisis' : 'análisis'}` }))))
    : el('p', { className: 'hint', text: String(search.query ?? '').trim().length < 3 ? 'Escribe al menos 3 caracteres.' : 'No aparece en ningún análisis guardado.' });
  return el('div', {}, form, list);
}

function filters(current, techniques) {
  return el('div', { className: 'history__filters' },
    field('Nivel', select('history-filter', 'level', [['', 'Todos'], ...LEVELS.map((l) => [l.level, l.label])], current.level)),
    field('Fecha', select('history-filter', 'range', RANGES, current.range)),
    field('Técnica', select('history-filter', 'technique', [['', 'Todas'], ...techniques.map((t) => [t, t])], current.technique)));
}

function table(items, selected) {
  const rows = items.map((e) => {
    const box = el('input', { attrs: { type: 'checkbox', 'data-action': 'history-select', 'data-id': e.id, 'aria-label': `Comparar ${e.name ?? 'este análisis'}` } });
    if (selected.includes(e.id)) box.setAttribute('checked', '');
    return [
      when(e.savedAt),
      defang(e.report.email?.from?.address ?? '—'),
      e.report.email?.subject ?? '—',
      el('span', { className: `level-tag level-tag--${e.report.level}`, text: levelLabel(e.report.level) }),
      e.name ?? '—',
      el('span', { className: 'history__row-actions' },
        button('Abrir', 'history-open', { 'data-id': e.id }),
        button('Borrar', 'history-delete', { 'data-id': e.id, 'aria-label': `Borrar ${e.name ?? 'este análisis'}` }),
        box),
    ];
  });
  return dataTable({ caption: 'Análisis guardados', columns: ['Fecha', 'Remitente', 'Asunto', 'Nivel', 'Nombre', 'Acciones'], rows, className: 'history__table' });
}

function pager({ offset = 0, total, items }) {
  const from = total ? offset + 1 : 0;
  const to = offset + items.length;
  return el('div', { className: 'history__pager' },
    offset > 0 ? button('Anteriores', 'history-page', { 'data-offset': String(Math.max(0, offset - 50)) }) : null,
    el('p', { className: 'hint', text: `Se muestran ${from}–${to} de ${total}` }),
    to < total ? button('Siguientes', 'history-page', { 'data-offset': String(to) }) : null);
}

function comparison(c) {
  const delta = c.scoreDelta;
  const sign = delta > 0 ? '+' : delta < 0 ? '−' : '±';
  const listOf = (title, values, fmt = (v) => v) => el('div', {}, el('h4', { text: title }),
    values.length ? el('ul', {}, ...values.map((v) => el('li', { text: fmt(v) }))) : el('p', { className: 'hint', text: 'Ninguno.' }));
  return el('section', { className: 'card history__compare', attrs: { 'aria-label': 'Comparación' } },
    el('h3', { text: `Comparar: ${c.a.name ?? 'A'} y ${c.b.name ?? 'B'}` }),
    el('p', { text: `Diferencia de puntuación: ${sign}${Math.abs(delta)}` }),
    el('div', { className: 'history__compare-grid' },
      listOf('IOCs en los dos', c.sharedIocs, defang),
      listOf(`Solo en ${c.a.name ?? 'A'}`, c.onlyA, defang),
      listOf(`Solo en ${c.b.name ?? 'B'}`, c.onlyB, defang),
      listOf('Señales en los dos', c.findings.shared),
      listOf(`Señales solo en ${c.a.name ?? 'A'}`, c.findings.onlyA),
      listOf(`Señales solo en ${c.b.name ?? 'B'}`, c.findings.onlyB)));
}

function importSummary(res) {
  if (!res) return null;
  return el('div', { className: 'history__import', attrs: { role: 'status' } },
    el('p', { text: `Importados ${res.imported}; rechazados ${res.rejected.length}` }),
    res.rejected.length ? el('ul', {}, ...res.rejected.map((r) => el('li', { text: r.index < 0 ? r.error : `Entrada ${r.index + 1}: ${r.error}` }))) : null);
}

function clearDialog(total) {
  const title = nextId('history-dialog');
  return el('dialog', { className: 'history__dialog', attrs: { 'aria-labelledby': title } },
    el('p', { text: `¿Borrar los ${total} análisis guardados? No se puede deshacer.`, attrs: { id: title } }),
    el('div', { className: 'history__dialog-actions' },
      button('Cancelar', 'history-clear-cancel'),
      button(`Borrar ${total} análisis`, 'history-clear-confirm', {}, 'btn btn--danger')));
}

/** options.history: {page: {items, total, skipped, offset}, filters, techniques, search, compare, selected, importResult}. */
export function historyPanel(_report, options = {}) {
  const h = options.history ?? {};
  const page = h.page ?? { items: [], total: 0, skipped: 0, offset: 0 };
  const tools = el('div', { className: 'history__tools' },
    button('Exportar historial (.json)', 'history-export'),
    button('Importar historial (.json)', 'history-import'),
    page.total ? button('Borrar todo', 'history-clear') : null);
  const parts = [
    el('p', { className: 'hint', text: 'Los análisis guardados en este navegador. El correo original no se guarda.' }),
    tools,
    importSummary(h.importResult),
  ];
  if (!page.total && !h.search) {
    parts.push(emptyState('Aún no hay nada guardado.', 'Activa el historial y analiza algún correo para verlo aquí.'));
    return el('div', { className: 'stack history' }, ...parts);
  }
  parts.push(searchBox(h.search), filters(h.filters ?? {}, h.techniques ?? []));
  if (page.skipped) parts.push(el('p', { className: 'graph__note', text: `${page.skipped} entradas guardadas no se han podido leer y se han saltado.` }));
  if (page.items.length) parts.push(table(page.items, h.selected ?? []), pager(page));
  else parts.push(el('p', { className: 'hint', text: 'Ningún análisis guardado cumple estos filtros.' }));
  if ((h.selected ?? []).length === 2) parts.push(button('Comparar los dos marcados', 'history-compare'));
  else parts.push(el('p', { className: 'hint', text: 'Marca dos análisis para compararlos.' }));
  if (h.compare) parts.push(comparison(h.compare));
  parts.push(clearDialog(page.total));
  return el('div', { className: 'stack history' }, ...parts);
}
