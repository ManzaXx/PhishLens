// Modo sencillo del informe: qué es, qué hacer y por qué, en lenguaje llano (spec 2.3, §2).
import { el } from '../dom.js';
import { verdictCard } from '../components/verdict-card.js';
import { stepList } from '../components/step-list.js';
import { signalRow } from '../components/signal-row.js';
import { emptyState } from '../components/empty-state.js';
import { t } from '../../i18n/index.js';
import { campaignName } from '../campaign-reasons.js';

const section = (title, ...children) => el('section', { className: 'simple__section' }, el('h3', { className: 'simple__title', text: title }), ...children);

/** Aviso si el correo abierto forma parte de una campaña del lote. */
function campaignNote(batch) {
  const c = batch?.campaigns?.find((x) => x.emails.includes(batch.current));
  if (!c) return null;
  const others = c.emails.length - 1;
  return el('div', { className: 'campaign-note' },
    el('p', { text: t('simple.campaign', { name: campaignName(c), count: others }) }),
    el('button', { className: 'btn btn--small', text: t('simple.viewCampaign'), attrs: { type: 'button', 'data-action': 'view-campaign', 'data-id': c.id } }));
}

/**
 * Posición de un motivo del veredicto en report.findings. En español son los mismos objetos; traducido, el
 * informe lleva copias (localize.js), así que se busca por id, detalle y evidencia, que se traducen igual.
 */
export function findingIndex(findings, f) {
  const same = findings.indexOf(f);
  if (same >= 0) return same;
  return findings.findIndex((x) => x.id === f.id && x.detail === f.detail && x.evidence === f.evidence && x.detector === f.detector);
}

/** Vista sencilla del informe. options.batch: el lote, si lo hay; options.analyzed: la franja «Qué se ha analizado». */
export function renderSimple(report, options = {}) {
  const { verdict } = report;
  const findings = report.findings ?? [];
  const why = verdict.top.length
    ? el('ul', { className: 'signals' }, ...verdict.top.map((f) => signalRow(f, { index: findingIndex(findings, f) })))
    : emptyState(t('simple.empty.title'), t('simple.empty.text'));
  return el('div', { className: 'simple' },
    verdictCard(verdict, { score: report.score, confidence: report.confidence }),
    options.analyzed ?? null,
    campaignNote(options.batch),
    section(t('simple.steps'), stepList(verdict.steps)),
    section(t('simple.why'), why, el('p', { className: 'simple__note', text: t('report.scoreNote') })),
    el('div', { className: 'simple__more' },
      el('button', { className: 'btn', text: t('simple.more'), attrs: { type: 'button', 'data-action': 'mode-analyst' } })));
}
