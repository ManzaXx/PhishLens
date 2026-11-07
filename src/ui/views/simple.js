// Modo sencillo del informe: qué es, qué hacer y por qué, en lenguaje llano (spec 2.3, §2).
import { el } from '../dom.js';
import { verdictCard } from '../components/verdict-card.js';
import { stepList } from '../components/step-list.js';
import { signalRow } from '../components/signal-row.js';
import { emptyState } from '../components/empty-state.js';

const section = (title, ...children) => el('section', { className: 'simple__section' }, el('h3', { className: 'simple__title', text: title }), ...children);

/** Aviso si el correo abierto forma parte de una campaña del lote. */
function campaignNote(batch) {
  const c = batch?.campaigns?.find((x) => x.emails.includes(batch.current));
  if (!c) return null;
  const others = c.emails.length - 1;
  return el('div', { className: 'campaign-note' },
    el('p', { text: `Este correo forma parte de la ${c.name}, con ${others} ${others === 1 ? 'correo más' : 'correos más'} del lote que comparten remitente, adjunto o plantilla.` }),
    el('button', { className: 'btn btn--small', text: 'Ver la campaña', attrs: { type: 'button', 'data-action': 'view-campaign', 'data-id': c.id } }));
}

/** Vista sencilla del informe. options.batch: el lote, si lo hay. */
export function renderSimple(report, options = {}) {
  const { verdict } = report;
  const why = verdict.top.length
    ? el('ul', { className: 'signals' }, ...verdict.top.map(signalRow))
    : emptyState('Sin señales de riesgo', 'No hemos encontrado nada sospechoso en este correo. Una nota baja no garantiza que sea seguro.');
  return el('div', { className: 'simple' },
    verdictCard(verdict, { score: report.score, confidence: report.confidence }),
    campaignNote(options.batch),
    section('Qué hacer ahora', stepList(verdict.steps)),
    section('Por qué lo decimos', why),
    el('div', { className: 'simple__more' },
      el('button', { className: 'btn', text: 'Ver todos los detalles (modo analista)', attrs: { type: 'button', 'data-action': 'mode-analyst' } })));
}
