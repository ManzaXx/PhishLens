// Vista «Panel» (spec 3.0, §3): de un vistazo, lo que hay en el historial. Recibe las estadísticas ya
// calculadas (dashboard-data.js) y solo pinta: texto con textContent, IOCs defanged, acciones por data-action.
import { el } from '../dom.js';
import { defang } from '../../intel/ioc.js';
import { LEVELS } from '../../core/scoring.js';
import { emptyState } from '../components/empty-state.js';
import { stackedBars, hBars } from '../components/bar-chart.js';

const SERIES = [...LEVELS].reverse().map((l) => ({ key: l.level, label: l.label }));
const TYPES = { domains: 'Dominio', ips: 'IP', hashes: 'SHA-256', sha1: 'SHA-1', md5: 'MD5' };
const button = (text, action, attrs = {}) => el('button', { className: 'btn', text, attrs: { type: 'button', 'data-action': action, ...attrs } });
const fmtDay = (iso) => new Date(`${iso}T00:00:00Z`).toLocaleDateString('es-ES', { day: 'numeric', month: 'short', timeZone: 'UTC' });
const when = (iso) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString('es-ES', { dateStyle: 'short', timeStyle: 'short' });
};
const card = (title, ...children) => el('section', { className: 'card dashboard__card', attrs: { 'aria-label': title } }, ...children);
const none = (msg) => el('p', { className: 'hint', text: msg });

function tiles({ totals }) {
  const tile = (label, value) => el('div', { className: 'stat-tile' },
    el('span', { className: 'stat-tile__value', text: String(value) }),
    el('span', { className: 'stat-tile__label', text: label }));
  return el('div', { className: 'dashboard__tiles' },
    tile('Análisis guardados', totals.analyses),
    tile('Probable phishing o peor', totals.phishingOrWorse),
    tile('Campañas', totals.campaigns),
    tile('IOCs distintos', totals.distinctIocs),
    tile('Con adjunto peligroso', `${totals.dangerousPct} %`));
}

function timelineCard({ timeline }) {
  const note = timeline.unit === 'day' ? 'Por día, últimos 30 días.' : 'Por semana.';
  const omitted = timeline.omitted ? ` ${timeline.omitted} análisis más antiguos no caben en la gráfica.` : '';
  return card('Niveles en el tiempo',
    stackedBars({ caption: 'Niveles en el tiempo', series: SERIES, buckets: timeline.buckets.map((b) => ({ label: fmtDay(b.start), counts: b.counts })) }),
    el('p', { className: 'hint', text: `${note}${omitted}` }));
}

function iocCard({ iocs }) {
  const body = iocs.length
    ? el('ul', { className: 'dashboard__iocs' }, ...iocs.map((i) => el('li', {},
      el('button', { className: 'btn dashboard__ioc', attrs: { type: 'button', 'data-action': 'dashboard-search', 'data-ioc': i.value, 'aria-label': `Buscar ${defang(i.value)} en el historial` } },
        el('span', { className: 'dashboard__ioc-value', text: defang(i.value) }),
        el('span', { className: 'hint', text: ` ${TYPES[i.type] ?? i.type} · ${i.count} análisis` })))))
    : none('Ningún IOC aparece en más de un análisis.');
  return card('IOCs más repetidos', el('h3', { text: 'IOCs más repetidos' }), body,
    iocs.length ? el('p', { className: 'hint', text: 'Pulsa uno para buscarlo en el historial.' }) : null);
}

function campaignsCard({ campaigns }) {
  const body = campaigns.length
    ? el('ul', { className: 'dashboard__campaign-list' }, ...campaigns.map((c) => el('li', {},
      el('p', { className: 'dashboard__campaign-name', text: c.name }),
      el('p', { className: 'hint', text: `${when(c.savedAt)} · ${c.emails} ${c.emails === 1 ? 'correo' : 'correos'}` }),
      c.reasons.length ? el('p', { text: c.reasons.join(' · ') }) : null,
      c.latestSha ? button('Abrir el último correo', 'dashboard-open', { 'data-sha': c.latestSha }) : null)))
    : none('Aún no hay campañas: aparecen al analizar varios correos a la vez.');
  return el('section', { className: 'card dashboard__card dashboard__campaigns', attrs: { 'aria-label': 'Campañas recientes' } },
    el('h3', { text: 'Campañas recientes' }), body);
}

function listChart(caption, rows, emptyMsg) {
  return card(caption, rows.length ? hBars({ caption, rows: rows.map((r) => ({ label: defang(r.value), value: r.count })) }) : el('div', {}, el('h3', { text: caption }), none(emptyMsg)));
}

/** options.dashboard: {stats} o null; options.historyEnabled. */
export function dashboardPanel(_report, options = {}) {
  if (!options.historyEnabled || !options.dashboard) {
    return el('div', { className: 'stack dashboard' },
      emptyState('Aún no hay nada guardado.', 'Activa el historial y analiza algún correo para ver aquí lo que te llega.'),
      options.historyEnabled ? null : button('Activar historial', 'history-enable'));
  }
  const { stats } = options.dashboard;
  if (!stats.totals.analyses) {
    return el('div', { className: 'stack dashboard' },
      emptyState('Aún no hay nada guardado.', 'Activa el historial y analiza algún correo para ver aquí lo que te llega.'));
  }
  return el('div', { className: 'stack dashboard' },
    el('p', { className: 'hint', text: 'Resumen de los análisis guardados en este navegador.' }),
    tiles(stats),
    timelineCard(stats),
    card('Técnicas ATT&CK más vistas', stats.techniques.length
      ? hBars({ caption: 'Técnicas ATT&CK más vistas', rows: stats.techniques.map((t) => ({ label: `${t.id} · ${t.name}`, value: t.count, detail: t.tactic })) })
      : el('div', {}, el('h3', { text: 'Técnicas ATT&CK más vistas' }), none('Ninguna técnica todavía.'))),
    iocCard(stats),
    el('div', { className: 'dashboard__pair' },
      listChart('Remitentes más frecuentes', stats.senders, 'Ningún correo sospechoso todavía.'),
      listChart('Dominios de envío más frecuentes', stats.domains, 'Ningún correo sospechoso todavía.')),
    campaignsCard(stats));
}
