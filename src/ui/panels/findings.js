// Panel «Señales»: todas las señales agrupadas por detector.
import { el } from '../dom.js';
import { findingCard } from '../components/finding-card.js';


export const DETECTOR_LABELS = {
  input: 'Entrada',
  auth: 'Autenticación',
  sender: 'Remitente',
  headers: 'Cabeceras técnicas',
  route: 'Ruta del correo',
  links: 'Enlaces',
  lookalike: 'Dominios parecidos',
  attachments: 'Adjuntos',
  html: 'Contenido HTML',
  mime: 'Estructura MIME',
  language: 'Lenguaje',
};

export function findingsPanel(report) {
  const panel = el('div');
  if (report.findings.length === 0) {
    panel.append(el('p', { className: 'empty', text: 'No se ha encontrado ninguna señal de phishing.' }));
    return panel;
  }
  const groups = new Map();
  for (const f of report.findings) {
    if (!groups.has(f.detector)) groups.set(f.detector, []);
    groups.get(f.detector).push(f);
  }
  for (const [detector, items] of groups) {
    const group = el('div', { className: 'group' }, el('h4', { className: 'group__title', text: DETECTOR_LABELS[detector] ?? detector }));
    for (const f of items) group.append(findingCard(f));
    panel.append(group);
  }
  for (const err of report.errors) {
    panel.append(el('p', { className: 'warning', text: `El detector "${err.detector}" no pudo completarse: ${err.message}` }));
  }
  return panel;
}
