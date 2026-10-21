// Pinta el informe. Todo el contenido del email se inserta con textContent:
// nunca se interpreta como HTML ni se generan enlaces clicables.

const SVG_NS = 'http://www.w3.org/2000/svg';

const DETECTOR_LABELS = {
  input: 'Entrada',
  auth: 'Autenticación',
  sender: 'Remitente',
  links: 'Enlaces',
  lookalike: 'Dominios parecidos',
  attachments: 'Adjuntos',
  language: 'Lenguaje',
};

const SEVERITY_LABELS = { high: 'Grave', medium: 'Media', low: 'Leve', info: 'Info' };

/** Crea un elemento con clase, texto e hijos. */
function el(tag, { className, text, attrs } = {}, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  for (const [k, v] of Object.entries(attrs ?? {})) node.setAttribute(k, v);
  for (const child of children) if (child) node.append(child);
  return node;
}

function svg(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

function gauge(score) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const root = el('div', { className: 'gauge', attrs: { role: 'img', 'aria-label': `Puntuación de riesgo: ${score} de 100` } });
  const ring = svg('svg', { viewBox: '0 0 120 120', 'aria-hidden': 'true' });
  ring.append(svg('circle', { class: 'gauge__track', cx: 60, cy: 60, r: radius, fill: 'none', 'stroke-width': 12 }));
  const value = svg('circle', {
    class: 'gauge__value', cx: 60, cy: 60, r: radius, fill: 'none', 'stroke-width': 12,
    'stroke-linecap': 'round', 'stroke-dasharray': circumference.toFixed(2),
  });
  value.style.strokeDashoffset = String(circumference);
  if (score === 0) value.style.opacity = '0';
  ring.append(value);
  // Animación desde 0 hasta la puntuación.
  requestAnimationFrame(() => requestAnimationFrame(() => {
    value.style.strokeDashoffset = String(circumference * (1 - score / 100));
  }));
  root.append(ring, el('div', { className: 'gauge__label' },
    el('span', { className: 'gauge__score', text: String(score) }),
    el('span', { className: 'gauge__max', text: 'de 100' })));
  return root;
}

function findingCard(f) {
  return el('article', { className: `finding sev-${f.severity}` },
    el('div', { className: 'finding__top' },
      el('h4', { className: 'finding__title', text: f.title }),
      el('span', { className: 'badge', text: f.points ? `${SEVERITY_LABELS[f.severity]} · +${f.points}` : SEVERITY_LABELS[f.severity] })),
    el('p', { className: 'finding__detail', text: f.detail }),
    f.evidence ? el('p', { className: 'finding__evidence', text: f.evidence }) : null);
}

function findingsSection(report) {
  const section = el('section', { attrs: { 'aria-label': 'Señales encontradas' } });
  section.append(el('h3', { text: `Señales encontradas (${report.findings.length})` }));
  if (report.findings.length === 0) {
    section.append(el('p', { className: 'empty', text: 'No se ha encontrado ninguna señal de phishing.' }));
    return section;
  }
  const groups = new Map();
  for (const f of report.findings) {
    if (!groups.has(f.detector)) groups.set(f.detector, []);
    groups.get(f.detector).push(f);
  }
  for (const [detector, items] of groups) {
    const group = el('div', { className: 'group' }, el('h4', { className: 'group__title', text: DETECTOR_LABELS[detector] ?? detector }));
    for (const f of items) group.append(findingCard(f));
    section.append(group);
  }
  for (const err of report.errors) {
    section.append(el('p', { className: 'warning', text: `El detector "${err.detector}" no pudo completarse: ${err.message}` }));
  }
  return section;
}

function emailCard(email) {
  const rows = [
    ['De', email.from ? (email.from.name ? `${email.from.name} <${email.from.address}>` : email.from.address) : null],
    ['Responder a', email.replyTo?.address],
    ['Return-Path', email.returnPath],
    ['Asunto', email.subject],
    ['Autenticación', email.authResults],
  ].filter(([, v]) => v);
  if (rows.length === 0) return null;
  const dl = el('dl', { className: 'kv' });
  for (const [k, v] of rows) dl.append(el('dt', { text: k }), el('dd', { text: v }));
  return el('div', { className: 'card' }, el('h3', { text: 'Cabeceras clave' }), dl);
}

function linksCard(links) {
  if (!links?.length) return null;
  const list = el('ul', { className: 'linklist' });
  for (const link of links.slice(0, 30)) {
    const item = el('li', {}, el('span', { text: link.text || '(sin texto)' }));
    if (link.text !== link.href) item.append(el('span', { className: 'mono', text: `→ ${link.href}` }));
    list.append(item);
  }
  const card = el('div', { className: 'card' }, el('h3', { text: `Enlaces (${links.length})` }), list);
  if (links.length > 30) card.append(el('p', { className: 'hint', text: `Se muestran 30 de ${links.length}.` }));
  card.append(el('p', { className: 'hint', text: 'Los enlaces se muestran como texto para que no puedas abrirlos por accidente.' }));
  return card;
}

function attachmentsCard(attachments) {
  if (!attachments?.length) return null;
  const list = el('ul', { className: 'linklist' });
  for (const a of attachments) list.append(el('li', {}, el('span', { text: a.filename }), el('span', { className: 'mono', text: a.contentType })));
  return el('div', { className: 'card' }, el('h3', { text: `Adjuntos (${attachments.length})` }), list);
}

/** Dibuja el informe completo dentro de `container`. Devuelve los botones de acción. */
export function renderReport(container, report) {
  container.replaceChildren();
  container.className = `wrap report level-${report.level}`;

  const actions = el('div', { className: 'report__actions' },
    el('button', { className: 'btn', text: 'Exportar JSON', attrs: { type: 'button', 'data-action': 'export' } }),
    el('button', { className: 'btn', text: 'Imprimir', attrs: { type: 'button', 'data-action': 'print' } }),
    el('button', { className: 'btn', text: 'Analizar otro', attrs: { type: 'button', 'data-action': 'reset' } }));

  const head = el('div', { className: 'card report__head' },
    gauge(report.score),
    el('div', {},
      el('span', { className: 'verdict', text: report.label }),
      el('h2', { className: 'visually-hidden', text: 'Resultado del análisis' }),
      el('p', { className: 'report__summary', text: report.summary }),
      actions));

  const side = el('aside', { className: 'side' },
    emailCard(report.email), linksCard(report.email.links), attachmentsCard(report.email.attachments));

  container.append(head, el('div', { className: 'report__body' }, el('div', { className: 'card' }, findingsSection(report)), side));
  container.hidden = false;
  return actions;
}

/** Informe serializado para descargar. */
export function reportToJson(report) {
  return JSON.stringify({ tool: 'PhishLens', generatedAt: new Date().toISOString(), ...report }, null, 2);
}
