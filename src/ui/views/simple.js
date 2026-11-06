// Modo sencillo del informe: qué es, qué hacer y por qué, en lenguaje llano (spec 2.3, §2).
import { el } from '../dom.js';
import { verdictCard } from '../components/verdict-card.js';
import { stepList } from '../components/step-list.js';
import { signalRow } from '../components/signal-row.js';
import { emptyState } from '../components/empty-state.js';

const section = (title, ...children) => el('section', { className: 'simple__section' }, el('h3', { className: 'simple__title', text: title }), ...children);

/** Vista sencilla del informe. */
export function renderSimple(report) {
  const { verdict } = report;
  const why = verdict.top.length
    ? el('ul', { className: 'signals' }, ...verdict.top.map(signalRow))
    : emptyState('Sin señales de riesgo', 'No hemos encontrado nada sospechoso en este correo. Una nota baja no garantiza que sea seguro.');
  return el('div', { className: 'simple' },
    verdictCard(verdict, { score: report.score, confidence: report.confidence }),
    section('Qué hacer ahora', stepList(verdict.steps)),
    section('Por qué lo decimos', why),
    el('div', { className: 'simple__more' },
      el('button', { className: 'btn', text: 'Ver todos los detalles (modo analista)', attrs: { type: 'button', 'data-action': 'mode-analyst' } })));
}
