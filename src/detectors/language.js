// Detector de lenguaje de ingeniería social (urgencia, amenazas, credenciales, premios).
import { finding } from '../core/finding.js';
import { LANGUAGE_PATTERNS } from '../data/lists.js';
import { htmlToText } from '../parser/html.js';

export const name = 'language';

/** Recorta la frase alrededor de la coincidencia para mostrarla como evidencia. */
function excerpt(text, index, length) {
  const start = Math.max(0, index - 30);
  const end = Math.min(text.length, index + length + 30);
  return `${start > 0 ? '…' : ''}${text.slice(start, end).replace(/\s+/g, ' ').trim()}${end < text.length ? '…' : ''}`;
}

export function detect(email) {
  const body = email.text?.trim() ? email.text : htmlToText(email.html ?? '');
  const text = `${email.subject ?? ''}\n${body}`;
  const out = [];
  for (const [category, rule] of Object.entries(LANGUAGE_PATTERNS)) {
    for (const pattern of rule.patterns) {
      const m = pattern.exec(text);
      if (!m) continue;
      out.push(finding({
        id: `language.${category}`,
        detector: name,
        severity: rule.severity,
        title: rule.title,
        detail: rule.detail,
        params: {},
        evidence: excerpt(text, m.index, m[0].length),
      }));
      break;
    }
  }
  return out;
}
