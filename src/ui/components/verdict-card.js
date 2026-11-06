import { el, icon, nextId } from '../dom.js';
import { CONFIDENCE } from './labels.js';

const TONE_ICON = new Map([['safe', 'check'], ['suspicious', 'alert'], ['phishing', 'alert']]);

/** Veredicto en lenguaje llano: titular, «95 de 100 · confianza alta» y el porqué en una frase. */
export function verdictCard(verdict, { score, confidence } = {}) {
  const tone = TONE_ICON.has(verdict.tone) ? verdict.tone : 'suspicious';
  const id = nextId('verdict');
  const level = confidence ? CONFIDENCE.get(confidence.level) : null;
  const facts = [Number.isFinite(score) ? `${score} de 100` : null, level ? `confianza ${level}` : null].filter(Boolean).join(' · ');
  return el('section', { className: `verdict-card verdict--${tone}`, attrs: { 'aria-labelledby': id } },
    el('div', { className: 'verdict-card__top' },
      icon(TONE_ICON.get(tone)),
      el('h2', { className: 'verdict-card__headline', text: verdict.headline, attrs: { id } }),
      facts ? el('p', { className: 'verdict-card__facts', text: facts }) : null),
    verdict.because ? el('p', { className: 'verdict-card__because', text: verdict.because }) : null);
}
