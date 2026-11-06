import { el } from '../dom.js';

const TONES = new Set(['neutral', 'safe', 'suspicious', 'phishing', 'info', 'accent']);

/** Pastilla corta (recuentos, etiquetas). */
export function chip(text, { tone = 'neutral' } = {}) {
  return el('span', { className: `chip chip--${TONES.has(tone) ? tone : 'neutral'}`, text });
}
