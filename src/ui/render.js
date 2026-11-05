// Pinta el informe. Todo el contenido del email se inserta con textContent:
// nunca se interpreta como HTML ni se generan enlaces clicables a partir del email.
import { highlight } from './highlight.js';
import { adviceFor } from '../core/advice.js';
import { defang, iocsToText, PLAIN } from '../intel/ioc.js';
import { htmlToText } from '../parser/html.js';
import { reveal } from '../lib/text.js';
import { hopWarnings } from '../detectors/route.js';
import { toUnicode } from '../parser/punycode.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

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

const SEVERITY_LABELS = { high: 'Grave', medium: 'Media', low: 'Leve', info: 'Info' };
const RELIABILITY_LABELS = { high: 'fiabilidad alta', medium: 'fiabilidad media', low: 'fiabilidad baja' };
const CONFIDENCE_LABELS = { high: 'alta', medium: 'media', low: 'baja' };
const decimal = (n) => String(n).replace('.', ',');

/**
 * Crea un elemento con clase, texto, atributos e hijos.
 * El texto pasa por reveal(): un carácter RLO o invisible del email se muestra como ⟦U+202E⟧
 * en lugar de reordenar o esconder lo que se ve en el informe (ataque "Trojan Source").
 */
function el(tag, { className, text, attrs } = {}, ...children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = reveal(text);
  for (const [k, v] of Object.entries(attrs ?? {})) node.setAttribute(k, v);
  for (const child of children) if (child) node.append(child);
  return node;
}

function svg(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

const ALLOWED_LINK = /^https:\/\/attack\.mitre\.org\/techniques\/T\d{4}(\/\d{3})?\/$/;

/** Enlace externo propio de la app (documentación de MITRE), nunca uno del email. */
function externalLink(href, text, className) {
  if (!ALLOWED_LINK.test(href)) return el('span', { className, text });
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

/** Riesgo por categoría: cada fila dice su número en texto; la barra solo acompaña. */
function categoryList(report) {
  const list = el('ul', { className: 'breakdown', attrs: { 'aria-label': 'Riesgo por categoría' } });
  for (const c of report.categories ?? []) {
    const bar = el('span', { className: 'breakdown__bar' });
    bar.style.setProperty('--w', `${(c.score / c.max) * 100}%`);
    list.append(el('li', {},
      el('span', { className: 'breakdown__label', text: c.label }),
      el('span', { className: 'breakdown__track', attrs: { 'aria-hidden': 'true' } }, bar),
      el('span', { className: 'breakdown__points', text: `${decimal(c.score)} / ${c.max}` })));
  }
  return list;
}

/** Pastilla de confianza con sus motivos desplegables. */
function confidenceBadge(confidence) {
  if (!confidence) return null;
  const box = el('div', { className: `confidence confidence--${confidence.level}` },
    el('span', { className: 'confidence__label', text: `Confianza del análisis: ${CONFIDENCE_LABELS[confidence.level]}` }));
  if (confidence.reasons.length) {
    const list = el('ul', { className: 'confidence__reasons' });
    for (const reason of confidence.reasons) list.append(el('li', { text: reason }));
    box.append(el('details', {}, el('summary', { text: '¿Por qué?' }), list));
  }
  return box;
}

function listCard(title, className, items) {
  const list = el('ul', { className });
  for (const item of items) list.append(el('li', { text: item }));
  return el('div', { className: 'card' }, el('h3', { text: title }), list);
}

function adviceBox(report) {
  const list = el('ul', { className: 'advice__list' });
  for (const line of adviceFor(report)) list.append(el('li', { text: line }));
  return el('div', { className: 'advice' }, el('h3', { text: 'Qué hacer ahora' }), list);
}

// ---------- Pestaña: señales ----------

function findingCard(f) {
  const meta = el('div', { className: 'finding__meta' });
  if (f.points && f.polarity !== 'trust') {
    for (const t of f.techniques ?? []) {
      const link = externalLink(t.url, `ATT&CK ${t.id}`, 'mitre-tag');
      link.title = `${t.name} (${t.tactic}). ${t.why}`;
      meta.append(link);
    }
  }
  return el('article', { className: `finding sev-${f.severity}` },
    el('div', { className: 'finding__top' },
      el('h4', { className: 'finding__title', text: f.title }),
      el('span', { className: 'badge', text: f.points ? `${SEVERITY_LABELS[f.severity]} · ${RELIABILITY_LABELS[f.reliability]}` : SEVERITY_LABELS[f.severity] })),
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
      : document.createTextNode(reveal(part.text)));
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
    const warnings = hopWarnings(email.route);
    email.route.forEach((hop, i) => {
      const tags = el('p', { className: 'route__tags' });
      for (const w of warnings[i]) {
        const kind = w.startsWith('Entrada') ? 'entry' : 'warn';
        tags.append(el('span', { className: `route__tag route__tag--${kind}`, text: w }));
      }
      ol.append(el('li', { className: warnings[i].length > (hop.entry ? 1 : 0) ? 'route__hop--warn' : '' },
        el('span', { className: 'route__step', text: String(i + 1) }),
        el('div', {},
          el('p', { className: 'route__hosts', text: `${hop.helo || hop.from || '¿?'}${hop.rdns && hop.rdns !== hop.helo ? ` (${hop.rdns})` : ''} → ${hop.by || '¿?'}` }),
          el('p', { className: 'route__meta', text: [hop.ip, hop.date].filter(Boolean).join(' · ') }),
          tags.childElementCount ? tags : null)));
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

// ---------- Pestaña: autenticación ----------

const AUTH_ROWS = [['spf', 'SPF'], ['dkim', 'DKIM'], ['dmarc', 'DMARC']];

/** Texto de la insignia: el color nunca es la única señal del estado. */
export function authStateLabel(m) {
  switch (m.state) {
    case 'verified': return 'Verificado por PhishLens';
    case 'declared-trusted': return `Declarado por ${m.source || 'el receptor'}`;
    case 'declared-untrusted': return 'Declarado sin confirmar';
    case 'unverifiable': return 'No verificable sin DNS';
    default: return 'Sin datos';
  }
}

const RESULT_TONE = { pass: 'safe', fail: 'high', softfail: 'medium', permerror: 'medium', temperror: 'low', neutral: 'low', none: 'low' };

function authPanel(report, { authStatus, dkimKey = '', spfRecord = '' } = {}) {
  const panel = el('div', { className: 'stack' });
  const auth = report.auth;
  if (!auth) return panel;

  const table = el('table', { className: 'auth-table' });
  table.append(el('thead', {}, el('tr', {},
    el('th', { text: 'Mecanismo', attrs: { scope: 'col' } }),
    el('th', { text: 'Resultado', attrs: { scope: 'col' } }),
    el('th', { text: 'Estado', attrs: { scope: 'col' } }))));
  const body = el('tbody');
  for (const [key, label] of AUTH_ROWS) {
    const m = auth[key];
    const tone = RESULT_TONE[m.result] ?? 'none';
    body.append(el('tr', { attrs: { 'data-auth': key } },
      el('th', { text: label, attrs: { scope: 'row' } }),
      el('td', {}, el('span', { className: `auth-result auth-result--${tone}`, text: m.result ?? '—' })),
      el('td', {},
        el('span', { className: `auth-state auth-state--${m.state}`, text: authStateLabel(m) }),
        m.detail ? el('p', { className: 'auth-detail', text: m.detail }) : null)));
  }
  table.append(body);
  panel.append(el('section', {},
    el('h4', { className: 'group__title', text: 'SPF, DKIM y DMARC' }),
    el('p', { className: 'hint', text: '«Verificado» significa que PhishLens lo ha comprobado en tu navegador. «Declarado» es lo que dice una cabecera, que solo vale si la añadió el servidor que recibió el correo.' }),
    el('div', { className: 'table-wrap' }, table)));

  if (auth.headers.length) {
    const ul = el('ul', { className: 'auth-headers' });
    for (const h of auth.headers) {
      const kind = h.forged ? 'forged' : h.trusted ? 'trusted' : 'untrusted';
      const text = { forged: 'Falsificada', trusted: 'De confianza', untrusted: 'Sin confirmar' }[kind];
      ul.append(el('li', {},
        el('span', { className: `auth-state auth-state--${kind}`, text }),
        el('span', { className: 'mono', text: h.authservId || '(sin nombre)' }),
        el('span', { className: 'auth-detail', text: h.why })));
    }
    panel.append(el('section', {}, el('h4', { className: 'group__title', text: `Cabeceras Authentication-Results (${auth.headers.length})` }), ul));
  }

  const isEmail = report.email.from !== null || report.email.authResults !== null;
  if (isEmail) {
    const details = el('details', { className: 'auth-local', attrs: authStatus ? { open: '' } : {} },
      el('summary', { text: 'Comprobar en local' }),
      el('p', { className: 'hint', text: 'Sin red: pega tú los registros DNS (por ejemplo, desde dig o un servicio de consulta DNS) y PhishLens los comprueba aquí mismo.' }),
      el('label', { text: 'Clave pública DKIM (registro TXT de selector._domainkey.dominio)', attrs: { for: 'dkim-key' } }),
      Object.assign(el('textarea', { attrs: { id: 'dkim-key', rows: '3', spellcheck: 'false', autocomplete: 'off', placeholder: 'v=DKIM1; k=rsa; p=MIIBIjANBg…' } }), { value: dkimKey }),
      el('button', { className: 'btn btn--small', text: 'Verificar firma', attrs: { type: 'button', 'data-action': 'verify-dkim' } }),
      el('label', { text: 'Registro SPF del dominio del sobre (Return-Path)', attrs: { for: 'spf-record' } }),
      Object.assign(el('textarea', { attrs: { id: 'spf-record', rows: '2', spellcheck: 'false', autocomplete: 'off', placeholder: 'v=spf1 ip4:192.0.2.0/24 -all' } }), { value: spfRecord }),
      el('button', { className: 'btn btn--small', text: 'Evaluar SPF', attrs: { type: 'button', 'data-action': 'eval-spf' } }),
      authStatus ? el('p', { className: 'auth-status', text: authStatus, attrs: { id: 'auth-status' } }) : null);
    panel.append(details);
  }
  return panel;
}

// ---------- Pestaña: IOCs ----------

const IOC_LABELS = [['urls', 'URLs'], ['domains', 'Dominios'], ['ips', 'IPs'], ['emails', 'Emails'], ['attachments', 'Adjuntos'], ['hashes', 'SHA-256']];

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
    for (const v of values.slice(0, 50)) {
      const shown = PLAIN.has(key) ? v : defang(v);
      // Dominios internacionales: también en Unicode, para ver qué letras hay de verdad.
      const unicode = key === 'domains' && /(^|\.)xn--/i.test(v) ? toUnicode(v) : null;
      ul.append(el('li', { text: unicode && unicode !== v ? `${shown} (${defang(unicode)})` : shown }));
    }
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
  table.append(el('thead', {}, el('tr', {}, el('th', { text: 'Técnica' }), el('th', { text: 'Nombre' }), el('th', { text: 'Táctica' }), el('th', { text: 'Señales' }))));
  const body = el('tbody');
  for (const t of report.techniques) {
    const count = report.findings.filter((f) => f.points && f.polarity !== 'trust' && f.techniques?.some((x) => x.id === t.id)).length;
    body.append(el('tr', {},
      el('td', {}, externalLink(t.url, t.id, 'mono')),
      el('td', { text: t.name, attrs: { title: t.why } }),
      el('td', { text: t.tactic }),
      el('td', { text: String(count) })));
  }
  table.append(body);
  panel.append(el('div', { className: 'table-wrap' }, table));
  return panel;
}

// ---------- Pestañas del informe ----------

function reportTabs(report, options) {
  const tabs = [
    ['signals', `Señales (${report.findings.length})`, findingsPanel],
    ['safe-view', 'Vista segura', safeViewPanel],
    ['auth', 'Autenticación', authPanel],
    ['headers', 'Cabeceras y ruta', headersPanel],
    ['iocs', 'IOCs', iocsPanel],
    ['mitre', `ATT&CK (${report.techniques.length})`, mitrePanel],
  ];
  const list = el('div', { className: 'tabs tabs--report', attrs: { role: 'tablist', 'aria-label': 'Secciones del informe' } });
  const panels = el('div', { className: 'report__panels' });
  const selected = tabs.some(([id]) => id === options.tab) ? options.tab : tabs[0][0];
  tabs.forEach(([id, label, build]) => {
    const on = id === selected;
    const tab = el('button', {
      text: label,
      attrs: { role: 'tab', id: `rtab-${id}`, 'aria-controls': `rpanel-${id}`, 'aria-selected': String(on), tabindex: on ? '0' : '-1', type: 'button' },
    });
    const panel = el('div', { className: 'panel', attrs: { role: 'tabpanel', id: `rpanel-${id}`, 'aria-labelledby': `rtab-${id}`, tabindex: '0' } }, build(report, options));
    panel.hidden = !on;
    list.append(tab);
    panels.append(panel);
  });
  return el('div', { className: 'card report__main' }, list, panels);
}

/**
 * Dibuja el informe completo dentro de `container`.
 * options.tab abre esa pestaña; options.authStatus muestra el resultado de una comprobación local.
 */
export function renderReport(container, report, options = {}) {
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
      report.mainReason ? el('p', { className: 'report__reason' }, el('strong', { text: report.mainReason })) : null,
      el('p', { className: 'report__summary', text: report.summary }),
      confidenceBadge(report.confidence),
      actions));

  const side = el('aside', { className: 'side' });
  side.append(el('div', { className: 'card' }, el('h3', { text: 'Riesgo por categoría' }), categoryList(report)));
  if (report.correlations?.length) side.append(listCard('Combinaciones peligrosas', 'correlations', report.correlations.map((c) => c.label)));
  const trusted = report.findings.filter((f) => f.polarity === 'trust');
  if (trusted.length) side.append(listCard('Señales a favor', 'trust-list', trusted.map((f) => f.title)));
  side.append(el('div', { className: 'card' }, adviceBox(report)));

  container.append(head, el('div', { className: 'report__body' }, reportTabs(report, options), side));
  container.hidden = false;
}

/** Informe serializado para descargar. */
export function reportToJson(report) {
  return JSON.stringify({ tool: 'PhishLens', version: '2.2.0-dev', generatedAt: new Date().toISOString(), ...report }, null, 2);
}

export { iocsToText };
