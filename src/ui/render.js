// Pinta el informe. Todo el contenido del email se inserta con textContent:
// nunca se interpreta como HTML ni se generan enlaces clicables a partir del email.
import { highlight } from './highlight.js';
import { adviceFor } from '../advice.js';
import { defang, iocsToText } from '../ioc.js';
import { htmlToText } from '../parser/eml.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

export const DETECTOR_LABELS = {
  input: 'Entrada',
  auth: 'Autenticación',
  sender: 'Remitente',
  headers: 'Cabeceras técnicas',
  links: 'Enlaces',
  lookalike: 'Dominios parecidos',
  attachments: 'Adjuntos',
  html: 'Contenido HTML',
  language: 'Lenguaje',
};

const SEVERITY_LABELS = { high: 'Grave', medium: 'Media', low: 'Leve', info: 'Info' };

/** Crea un elemento con clase, texto, atributos e hijos. */
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

/** Enlace externo propio de la app (documentación de MITRE), nunca uno del email. */
function externalLink(href, text, className) {
  return el('a', { className, text, attrs: { href, target: '_blank', rel: 'noopener noreferrer' } });
}

// ---------- Cabecera del informe ----------

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
  const number = el('span', { className: 'gauge__score', text: '0' });
  root.append(ring, el('div', { className: 'gauge__label' }, number, el('span', { className: 'gauge__max', text: 'de 100' })));

  // Animación del anillo y del número (se respeta prefers-reduced-motion).
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    value.style.strokeDashoffset = String(circumference * (1 - score / 100));
  }));
  if (reduce) {
    number.textContent = String(score);
  } else {
    const start = performance.now();
    const tick = (t) => {
      const p = Math.min(1, (t - start) / 800);
      number.textContent = String(Math.round(score * (1 - (1 - p) ** 3)));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
  return root;
}

function breakdown(report) {
  const totals = new Map();
  for (const f of report.findings) {
    if (!f.points) continue;
    totals.set(f.detector, (totals.get(f.detector) ?? 0) + f.points);
  }
  if (totals.size === 0) return null;
  const max = Math.max(...totals.values());
  const list = el('ul', { className: 'breakdown', attrs: { 'aria-label': 'Puntos por categoría' } });
  for (const [detector, points] of [...totals].sort((a, b) => b[1] - a[1])) {
    const bar = el('span', { className: 'breakdown__bar' });
    bar.style.setProperty('--w', `${Math.max(6, (points / max) * 100)}%`);
    list.append(el('li', {},
      el('span', { className: 'breakdown__label', text: DETECTOR_LABELS[detector] ?? detector }),
      el('span', { className: 'breakdown__track' }, bar),
      el('span', { className: 'breakdown__points', text: `+${points}` })));
  }
  return list;
}

function adviceBox(report) {
  const list = el('ul', { className: 'advice__list' });
  for (const line of adviceFor(report)) list.append(el('li', { text: line }));
  return el('div', { className: 'advice' }, el('h3', { text: 'Qué hacer ahora' }), list);
}

// ---------- Pestaña: señales ----------

function findingCard(f) {
  const meta = el('div', { className: 'finding__meta' });
  if (f.mitre && f.points) meta.append(externalLink(f.mitre.url, `ATT&CK ${f.mitre.id}`, 'mitre-tag'));
  return el('article', { className: `finding sev-${f.severity}` },
    el('div', { className: 'finding__top' },
      el('h4', { className: 'finding__title', text: f.title }),
      el('span', { className: 'badge', text: f.points ? `${SEVERITY_LABELS[f.severity]} · +${f.points}` : SEVERITY_LABELS[f.severity] })),
    el('p', { className: 'finding__detail', text: f.detail }),
    f.evidence ? el('p', { className: 'finding__evidence', text: f.evidence }) : null,
    meta.childElementCount ? meta : null);
}

function findingsPanel(report) {
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

// ---------- Pestaña: vista segura ----------

function safeViewPanel(report) {
  const text = report.email.text?.trim() ? report.email.text : htmlToText(report.email.html ?? '');
  const panel = el('div');
  if (!text.trim()) {
    panel.append(el('p', { className: 'empty empty--muted', text: 'No hay texto que mostrar.' }));
    return panel;
  }
  panel.append(el('p', { className: 'hint', text: 'El mensaje como texto plano: sin imágenes, sin enlaces activos y con las frases sospechosas resaltadas.' }));
  const box = el('div', { className: 'safe-view', attrs: { tabindex: '0', 'aria-label': 'Texto del email' } });
  for (const part of highlight(text)) {
    box.append(part.kind
      ? el('mark', { className: `hl hl--${part.kind}`, text: part.text, attrs: { title: part.kind === 'url' ? 'Enlace (desactivado)' : 'Frase de ingeniería social' } })
      : document.createTextNode(part.text));
  }
  panel.append(box);

  const links = report.email.links ?? [];
  if (links.length) {
    const list = el('ul', { className: 'linklist' });
    for (const link of links.slice(0, 30)) {
      const item = el('li', {}, el('span', { text: link.text || '(sin texto)' }));
      if (link.text !== link.href) item.append(el('span', { className: 'mono', text: `→ ${link.href}` }));
      list.append(item);
    }
    panel.append(el('section', { className: 'safe-links' },
      el('h4', { className: 'group__title', text: `Enlaces: lo que se ve → a dónde llevan (${links.length})` }), list));
  }
  return panel;
}

// ---------- Pestaña: cabeceras y ruta ----------

function headersPanel(report) {
  const { email } = report;
  const panel = el('div', { className: 'stack' });
  const rows = [
    ['De', email.from ? (email.from.name ? `${email.from.name} <${email.from.address}>` : email.from.address) : null],
    ['Responder a', email.replyTo?.address],
    ['Return-Path', email.returnPath],
    ['Asunto', email.subject],
    ['Fecha', email.date],
    ['Autenticación', email.authResults],
  ].filter(([, v]) => v);
  if (rows.length) {
    const dl = el('dl', { className: 'kv' });
    for (const [k, v] of rows) dl.append(el('dt', { text: k }), el('dd', { text: v }));
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: 'Cabeceras clave' }), dl));
  }
  if (email.route?.length) {
    const ol = el('ol', { className: 'route' });
    email.route.forEach((hop, i) => {
      ol.append(el('li', {},
        el('span', { className: 'route__step', text: String(i + 1) }),
        el('div', {},
          el('p', { className: 'route__hosts', text: `${hop.from || '¿?'} → ${hop.by || '¿?'}` }),
          el('p', { className: 'route__meta', text: [hop.ip, hop.date].filter(Boolean).join(' · ') }))));
    });
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: `Ruta del email (${email.route.length} saltos)` }), ol));
  }
  if (email.attachments?.length) {
    const ul = el('ul', { className: 'linklist' });
    for (const a of email.attachments) ul.append(el('li', {}, el('span', { text: a.filename }), el('span', { className: 'mono', text: a.contentType })));
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: `Adjuntos (${email.attachments.length})` }), ul));
  }
  if (!panel.childElementCount) panel.append(el('p', { className: 'empty empty--muted', text: 'Sin cabeceras: pega el email original para ver esta parte.' }));
  return panel;
}

// ---------- Pestaña: IOCs ----------

const IOC_LABELS = [['urls', 'URLs'], ['domains', 'Dominios'], ['ips', 'IPs'], ['emails', 'Emails'], ['attachments', 'Adjuntos']];

function iocsPanel(report) {
  const panel = el('div', { className: 'stack' });
  const total = IOC_LABELS.reduce((n, [k]) => n + (report.iocs[k]?.length ?? 0), 0);
  if (!total) {
    panel.append(el('p', { className: 'empty empty--muted', text: 'No hay indicadores que extraer.' }));
    return panel;
  }
  panel.append(el('div', { className: 'ioc-head' },
    el('p', { className: 'hint', text: 'Indicadores de compromiso en formato "defanged" (hxxp, [.]) para compartirlos sin riesgo de clic.' }),
    el('button', { className: 'btn btn--small', text: 'Copiar IOCs', attrs: { type: 'button', 'data-action': 'copy-iocs' } })));
  const grid = el('div', { className: 'ioc-grid' });
  for (const [key, label] of IOC_LABELS) {
    const values = report.iocs[key] ?? [];
    if (!values.length) continue;
    const ul = el('ul', { className: 'ioc-list' });
    for (const v of values.slice(0, 50)) ul.append(el('li', { text: key === 'attachments' ? v : defang(v) }));
    grid.append(el('section', {}, el('h4', { className: 'group__title', text: `${label} (${values.length})` }), ul));
  }
  panel.append(grid);
  return panel;
}

// ---------- Pestaña: MITRE ATT&CK ----------

function mitrePanel(report) {
  const panel = el('div');
  if (!report.techniques.length) {
    panel.append(el('p', { className: 'empty empty--muted', text: 'Ninguna técnica de ataque identificada.' }));
    return panel;
  }
  panel.append(el('p', { className: 'hint', text: 'Técnicas del marco MITRE ATT&CK que encajan con las señales encontradas.' }));
  const table = el('table', { className: 'mitre' });
  table.append(el('thead', {}, el('tr', {}, el('th', { text: 'Técnica' }), el('th', { text: 'Nombre' }), el('th', { text: 'Señales' }))));
  const body = el('tbody');
  for (const t of report.techniques) {
    const count = report.findings.filter((f) => f.mitre?.id === t.id && f.points).length;
    body.append(el('tr', {},
      el('td', {}, externalLink(t.url, t.id, 'mono')),
      el('td', { text: t.name }),
      el('td', { text: String(count) })));
  }
  table.append(body);
  panel.append(el('div', { className: 'table-wrap' }, table));
  return panel;
}

// ---------- Pestañas del informe ----------

function reportTabs(report) {
  const tabs = [
    ['signals', `Señales (${report.findings.length})`, findingsPanel],
    ['safe-view', 'Vista segura', safeViewPanel],
    ['headers', 'Cabeceras y ruta', headersPanel],
    ['iocs', 'IOCs', iocsPanel],
    ['mitre', `ATT&CK (${report.techniques.length})`, mitrePanel],
  ];
  const list = el('div', { className: 'tabs tabs--report', attrs: { role: 'tablist', 'aria-label': 'Secciones del informe' } });
  const panels = el('div', { className: 'report__panels' });
  tabs.forEach(([id, label, build], i) => {
    const tab = el('button', {
      text: label,
      attrs: { role: 'tab', id: `rtab-${id}`, 'aria-controls': `rpanel-${id}`, 'aria-selected': String(i === 0), tabindex: i === 0 ? '0' : '-1', type: 'button' },
    });
    const panel = el('div', { className: 'panel', attrs: { role: 'tabpanel', id: `rpanel-${id}`, 'aria-labelledby': `rtab-${id}`, tabindex: '0' } }, build(report));
    panel.hidden = i !== 0;
    list.append(tab);
    panels.append(panel);
  });
  return el('div', { className: 'card report__main' }, list, panels);
}

/** Dibuja el informe completo dentro de `container`. */
export function renderReport(container, report) {
  container.replaceChildren();
  container.className = `wrap report level-${report.level}`;

  const actions = el('div', { className: 'report__actions' },
    el('button', { className: 'btn', text: 'Exportar JSON', attrs: { type: 'button', 'data-action': 'export' } }),
    el('button', { className: 'btn', text: 'Copiar IOCs', attrs: { type: 'button', 'data-action': 'copy-iocs' } }),
    el('button', { className: 'btn', text: 'Imprimir', attrs: { type: 'button', 'data-action': 'print' } }),
    el('button', { className: 'btn', text: 'Analizar otro', attrs: { type: 'button', 'data-action': 'reset' } }));

  const head = el('div', { className: 'card report__head' },
    gauge(report.score),
    el('div', { className: 'report__verdict' },
      el('span', { className: 'verdict', text: report.label }),
      el('h2', { className: 'visually-hidden', text: 'Resultado del análisis' }),
      el('p', { className: 'report__summary', text: report.summary }),
      actions));

  const side = el('aside', { className: 'side' });
  const bars = breakdown(report);
  if (bars) side.append(el('div', { className: 'card' }, el('h3', { text: 'Puntos por categoría' }), bars));
  side.append(el('div', { className: 'card' }, adviceBox(report)));

  container.append(head, el('div', { className: 'report__body' }, reportTabs(report), side));
  container.hidden = false;
}

/** Informe serializado para descargar. */
export function reportToJson(report) {
  return JSON.stringify({ tool: 'PhishLens', version: '2.0.0', generatedAt: new Date().toISOString(), ...report }, null, 2);
}

export { iocsToText };
