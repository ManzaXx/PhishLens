// Modo analista: navegación agrupada, el panel de la vista elegida y el lateral de contexto.
import { el, nextId } from '../dom.js';
import { meter } from '../components/meter.js';
import { navRail } from '../components/nav-rail.js';
import { adviceFor } from '../../core/advice.js';
import { IOC_SECTIONS } from '../../intel/ioc.js';
import { NAV_GROUPS, VIEW_LABELS, hasView } from '../route.js';
import { summaryPanel } from '../panels/summary.js';
import { findingsPanel } from '../panels/findings.js';
import { safeViewPanel } from '../panels/safe-view.js';
import { authPanel } from '../panels/auth.js';
import { headersPanel } from '../panels/headers.js';
import { iocsPanel } from '../panels/iocs.js';
import { mitrePanel } from '../panels/mitre.js';
import { attachmentsPanel } from '../panels/attachments.js';
import { urlsPanel } from '../panels/urls.js';
import { campaignsPanel } from '../panels/campaigns.js';
import { historyPanel } from '../panels/history.js';
import { dashboardPanel } from '../panels/dashboard.js';
import { t } from '../../i18n/index.js';

const PANELS = new Map([
  ['resumen', summaryPanel], ['senales', findingsPanel], ['vista-segura', safeViewPanel], ['autenticacion', authPanel],
  ['cabeceras', headersPanel], ['adjuntos', attachmentsPanel], ['urls', urlsPanel], ['iocs', iocsPanel],
  ['campanas', campaignsPanel], ['attack', mitrePanel], ['panel', dashboardPanel], ['historial', historyPanel],
]);

const IOC_KEYS = IOC_SECTIONS.map(([key]) => key);

/** Riesgo por categoría: cada fila dice su número en texto; la barra solo acompaña. */
function categoryList(report) {
  const list = el('ul', { className: 'meter-list', attrs: { 'aria-label': t('analyst.categories') } });
  for (const c of report.categories ?? []) list.append(el('li', {}, meter({ label: c.label, value: c.score, max: c.max })));
  return list;
}

function listCard(title, className, items) {
  const list = el('ul', { className });
  for (const item of items) list.append(el('li', { text: item }));
  return el('div', { className: 'card' }, el('h3', { text: title }), list);
}

function adviceBox(report) {
  const list = el('ul', { className: 'advice__list' });
  for (const line of adviceFor(report)) list.append(el('li', { text: line }));
  return el('div', { className: 'advice' }, el('h3', { text: t('analyst.advice') }), list);
}

function sidebar(report) {
  const side = el('aside', { className: 'side', attrs: { 'aria-label': t('analyst.side') } });
  side.append(el('div', { className: 'card' }, el('h3', { text: t('analyst.categories') }), categoryList(report)));
  if (report.correlations?.length) side.append(listCard(t('analyst.correlations'), 'correlations', report.correlations.map((c) => c.label)));
  const trusted = report.findings.filter((f) => f.polarity === 'trust');
  if (trusted.length) side.append(listCard(t('analyst.trust'), 'trust-list', trusted.map((f) => f.title)));
  side.append(el('div', { className: 'card' }, adviceBox(report)));
  return side;
}

/** Vista del modo analista. `view` ya debe estar resuelta (resolveView). options pasa al panel de autenticación. */
export function renderAnalyst(report, view, options = {}) {
  const current = PANELS.has(view) ? view : 'resumen';
  const groups = NAV_GROUPS.map((g) => ({
    label: g.label,
    views: g.views.filter((v) => hasView(v, report, options)).map((id) => ({ id, label: VIEW_LABELS[id] })),
  }));
  const counts = {
    senales: report.findings.length,
    adjuntos: report.email?.attachments?.length ?? 0,
    urls: new Set((report.email?.links ?? []).map((l) => l.href)).size,
    iocs: IOC_KEYS.reduce((n, k) => n + (report.iocs?.[k]?.length ?? 0), 0),
    campanas: options.batch?.campaigns?.length ?? 0,
    attack: report.techniques.length,
  };
  // Solo se cuenta lo que se sabe: la página del historial o, estando en el Panel, el total de sus cifras.
  const saved = options.history?.page?.total ?? (current === 'panel' ? options.dashboard?.stats?.totals?.analyses : undefined);
  if (saved != null) counts.historial = saved;
  const id = nextId('view');
  const panel = el('section', { className: `view view--${current}`, attrs: { 'aria-labelledby': id } },
    el('h2', { className: 'view__title', text: VIEW_LABELS[current], attrs: { id, tabindex: '-1' } }),
    PANELS.get(current)(report, options));
  // El historial no habla del informe de fondo: ocupa todo el ancho, sin su lateral.
  if (current === 'historial' || current === 'panel') return el('div', { className: 'analyst analyst--wide' }, navRail({ groups, current, counts }), panel);
  return el('div', { className: 'analyst' }, navRail({ groups, current, counts }), panel, sidebar(report));
}

