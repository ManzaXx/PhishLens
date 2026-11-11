// Vista «Panel» (spec 3.0, §3): de un vistazo, lo que hay en el historial. Recibe las estadísticas ya
// calculadas (dashboard-data.js) y solo pinta: texto con textContent, IOCs defanged, acciones por data-action.
import { el } from '../dom.js';
import { defang } from '../../intel/ioc.js';
import { LEVELS } from '../../core/scoring.js';
import { emptyState } from '../components/empty-state.js';
import { stackedBars, hBars } from '../components/bar-chart.js';
import { t, fmtDate } from '../../i18n/index.js';

const series = () => [...LEVELS].reverse().map((l) => ({ key: l.level, label: t(`level.${l.level}`) }));
const TYPES = new Set(['domains', 'ips', 'hashes', 'sha1', 'md5']);
const typeLabel = (type) => (TYPES.has(type) ? t(`ioc.type.${type}`) : type);
const button = (text, action, attrs = {}) => el('button', { className: 'btn', text, attrs: { type: 'button', 'data-action': action, ...attrs } });
const fmtDay = (iso) => fmtDate(new Date(`${iso}T00:00:00Z`), { day: 'numeric', month: 'short', timeZone: 'UTC' });
const when = (iso) => fmtDate(new Date(iso), { dateStyle: 'short', timeStyle: 'short' });
const card = (title, ...children) => el('section', { className: 'card dashboard__card', attrs: { 'aria-label': title } }, ...children);
const none = (msg) => el('p', { className: 'hint', text: msg });

function tiles({ totals }) {
  const tile = (label, value) => el('div', { className: 'stat-tile' },
    el('span', { className: 'stat-tile__value', text: String(value) }),
    el('span', { className: 'stat-tile__label', text: label }));
  return el('div', { className: 'dashboard__tiles' },
    tile(t('dashboard.tile.analyses'), totals.analyses),
    tile(t('dashboard.tile.phishing'), totals.phishingOrWorse),
    tile(t('dashboard.tile.campaigns'), totals.campaigns),
    tile(t('dashboard.tile.iocs'), totals.distinctIocs),
    tile(t('dashboard.tile.dangerous'), `${totals.dangerousPct} %`));
}

function timelineCard({ timeline }) {
  const note = timeline.unit === 'day' ? t('dashboard.timeline.day') : t('dashboard.timeline.week');
  const omitted = timeline.omitted ? ` ${t('dashboard.timeline.omitted', { count: timeline.omitted })}` : '';
  return card(t('dashboard.timeline'),
    stackedBars({ caption: t('dashboard.timeline'), series: series(), buckets: timeline.buckets.map((b) => ({ label: fmtDay(b.start), counts: b.counts })) }),
    el('p', { className: 'hint', text: `${note}${omitted}` }));
}

function iocCard({ iocs }) {
  const body = iocs.length
    ? el('ul', { className: 'dashboard__iocs' }, ...iocs.map((i) => el('li', {},
      el('button', { className: 'btn dashboard__ioc', attrs: { type: 'button', 'data-action': 'dashboard-search', 'data-ioc': i.value } },
        el('span', { className: 'dashboard__ioc-value', text: defang(i.value) }),
        el('span', { className: 'hint', text: ` ${typeLabel(i.type)} · ${t('dashboard.analyses', { count: i.count })}` })))))
    : none(t('dashboard.iocs.none'));
  return card(t('dashboard.iocs'), el('h3', { text: t('dashboard.iocs') }), body,
    iocs.length ? el('p', { className: 'hint', text: t('dashboard.iocs.hint') }) : null);
}

function campaignsCard({ campaigns }) {
  const body = campaigns.length
    ? el('ul', { className: 'dashboard__campaign-list' }, ...campaigns.map((c) => el('li', {},
      el('p', { className: 'dashboard__campaign-name', text: c.name }),
      el('p', { className: 'hint', text: `${when(c.savedAt)} · ${t('campaigns.emails.count', { count: c.emails })}` }),
      c.reasons.length ? el('p', { text: c.reasons.join(' · ') }) : null,
      c.latestSha ? button(t('dashboard.campaigns.open'), 'dashboard-open', { 'data-sha': c.latestSha }) : null)))
    : none(t('dashboard.campaigns.none'));
  return el('section', { className: 'card dashboard__card dashboard__campaigns', attrs: { 'aria-label': t('dashboard.campaigns') } },
    el('h3', { text: t('dashboard.campaigns') }), body);
}

function listChart(caption, rows, emptyMsg) {
  return card(caption, rows.length ? hBars({ caption, rows: rows.map((r) => ({ label: defang(r.value), value: r.count })) }) : el('div', {}, el('h3', { text: caption }), none(emptyMsg)));
}

/** options.dashboard: {stats} o null; options.historyEnabled. */
export function dashboardPanel(_report, options = {}) {
  if (!options.historyEnabled || !options.dashboard) {
    return el('div', { className: 'stack dashboard' },
      emptyState(t('history.empty.title'), t('dashboard.empty.text')),
      options.historyEnabled ? null : button(t('dashboard.enable'), 'history-enable'));
  }
  const { stats } = options.dashboard;
  if (!stats.totals.analyses) {
    return el('div', { className: 'stack dashboard' },
      emptyState(t('history.empty.title'), t('dashboard.empty.text')));
  }
  return el('div', { className: 'stack dashboard' },
    el('p', { className: 'hint', text: t('dashboard.hint') }),
    tiles(stats),
    timelineCard(stats),
    card(t('dashboard.techniques'), stats.techniques.length
      ? hBars({ caption: t('dashboard.techniques'), rows: stats.techniques.map((tech) => ({ label: `${tech.id} · ${tech.name}`, value: tech.count, detail: tech.tactic })) })
      : el('div', {}, el('h3', { text: t('dashboard.techniques') }), none(t('dashboard.techniques.none')))),
    iocCard(stats),
    el('div', { className: 'dashboard__pair' },
      listChart(t('dashboard.senders'), stats.senders, t('dashboard.suspicious.none')),
      listChart(t('dashboard.domains'), stats.domains, t('dashboard.suspicious.none'))),
    campaignsCard(stats));
}
