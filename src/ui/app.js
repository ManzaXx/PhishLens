// Controlador de la página: entradas, ejemplos, tema y acciones del informe.
import { analyzeInput, verifyDkimForInput } from '../core/engine.js';
import { analyzeBatch } from '../core/batch.js';
import { buildGraph } from '../intel/graph.js';
import { findCampaigns } from '../intel/campaigns.js';
import { SAMPLES, BATCHES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { renderReport, reportToJson, iocsToText, stixJson } from './render.js';
import { forensicReport, forensicJson, forensicFileName } from '../intel/forensic.js';
import { renderForensic } from './views/forensic.js';
import { forensicDialog, notesCount, notesSaveMessage } from './components/forensic-dialog.js';
import { sha256 } from '../lib/sha256.js';
import { FACTS, levelLegend } from '../core/facts.js';
import { menuKey } from './components/menu-button.js';
import { graphKey } from './components/graph.js';
import { parseRoute, formatRoute, initialMode, resolveView, isAnalystHash, MODE_KEY } from './route.js';
import { createHistoryControl } from './history-control.js';
import { dashboardData } from './dashboard-data.js';
import { VERSION } from './render.js';

import { LIMITS } from '../lib/limits.js';
import { reveal } from '../lib/text.js';
import { decimal } from './dom.js';
import { validateRules, formatRuleError, RULES_LIMITS } from '../rules/validate.js';
import { previewRules } from '../rules/preview.js';
import { rulesPanel } from './components/rules-panel.js';
import { HISTORY_MAX } from '../storage/history.js';
import { t, getLang, setLang, onLangChange, initialLang, LANG_KEY, LOCALE, fmtDate } from '../i18n/index.js';
import { translatePage } from './translate-page.js';

const MAX_BYTES = LIMITS.inputBytes;
const MAX_MB = Math.round(MAX_BYTES / 1024 / 1024);

// Anti-clickjacking: la CSP en <meta> no admite frame-ancestors, así que si otra web
// incrusta PhishLens en un iframe se oculta la herramienta y se ofrece abrirla aparte.
if (window.top !== window.self) {
  document.body.replaceChildren();
  const a = document.createElement('a');
  a.href = window.location.href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  a.textContent = t('app.frame');
  document.body.append(a);
  throw new Error('PhishLens no se ejecuta dentro de un iframe');
}
const $ = (sel) => document.querySelector(sel);

// Textos de estado fuera del informe: se guarda cómo escribirlos para repetirlo al cambiar de idioma.
const live = new Map();
/** Pone en `node` el texto que da `text()` y lo recuerda; con null lo vacía y lo olvida. */
function show(node, text) {
  if (!node) return;
  if (text == null) {
    live.delete(node);
    node.textContent = '';
    return;
  }
  live.set(node, text);
  node.textContent = text();
}
const say = (node, key, params) => show(node, () => t(key, params));
const searchMessage = (n) => (n ? t('app.search', { count: n }) : t('app.search.none'));

const state = {
  tab: 'eml', fileText: null, rules: null, lastReport: null, lastInput: null, analyst: {}, route: { mode: 'simple', view: 'resumen' },
  // Lote en memoria mientras la pestaña esté abierta: {entries, skipped, warning, graph, campaigns, current}.
  batch: null, batchTexts: new Map(), batchAbort: null, campaign: null,
  // Vista «Historial»: lo que se ha leído del historial para pintarla y el aviso del informe abierto desde él.
  historyData: null, historyQuery: { filters: {}, offset: 0 }, savedNote: '', dashboard: null, dashboardCache: {},
  // Informe forense: cuándo se analizó, la entrada del historial si se abrió desde él y las notas del analista.
  analyzedAt: null, saved: null, notes: '',
};

const tabs = [...document.querySelectorAll('[role="tab"]')];
const dropzone = $('#dropzone');
const fileInput = $('#file-input');
const rawInput = $('#raw-input');
const urlInput = $('#url-input');
const errorBox = $('#input-error');
const reportBox = $('#report');

// ---------- Tema ----------
function storage(fn) {
  try {
    return fn(window.localStorage);
  } catch {
    return null;
  }
}

/** El motor con las reglas propias activas (spec 3.0, §5.2). */
const analyzeWith = (input) => analyzeInput({ ...input, rules: state.rules?.rules ?? [] });

// ---------- Historial (apagado por defecto; nada de esto puede romper un análisis) ----------
const historyToggle = $('#history-toggle');
const historyStatus = $('#history-status');
const historyControl = createHistoryControl({ storage: storage((s) => s), factory: globalThis.indexedDB, version: VERSION });
let evictedShown = false;
historyControl.on('unavailable', () => {
  // Se apaga pero se puede volver a intentar: la cuota se puede liberar o el bloqueo quitar.
  historyToggle.checked = false;
  say(historyStatus, 'app.history.unavailable');
});
historyControl.on('evicted', () => {
  if (evictedShown) return;
  evictedShown = true;
  say(historyStatus, 'app.history.evicted', { max: HISTORY_MAX });
});
historyToggle.addEventListener('change', async () => {
  if (historyToggle.checked) {
    const res = await historyControl.enable();
    if (res.ok) say(historyStatus, 'app.history.on');
    // La base queda como la pestaña: las reglas activas se guardan y, si no hay, se borran las viejas
    // (pudieron quitarse con el historial apagado y volverían al recargar).
    if (res.ok) await (state.rules ? historyControl.saveRules(state.rules.source) : historyControl.clearRules());
  } else {
    historyControl.disable();
    say(historyStatus, 'app.history.off');
  }
  // Con el Panel abierto, sus cifras siguen al interruptor (apagado: estado vacío con «Activar historial»).
  if (state.lastReport && state.route.mode === 'analyst' && state.route.view === 'panel') await refreshDashboard();
});
const historyOpen = $('#history-open');
historyControl.on('change', () => updateHistoryButton());
historyControl.ready().then(async () => {
  historyToggle.checked = historyControl.enabled();
  updateHistoryButton();
  const saved = await historyControl.rules();
  if (saved && !state.rules) {
    state.rules = { source: saved.source, rules: saved.rules };
    say(rulesStatus, 'app.rules.fromHistory', { count: saved.rules.length });
  }
  await showActiveRules();
});

/** «Ver historial (N)» en la portada, solo si hay algo guardado. */
async function updateHistoryButton() {
  const h = historyControl.history();
  const n = h ? await h.count().catch(() => 0) : 0;
  historyOpen.hidden = !n;
  say(historyOpen, 'app.history.open', { n });
}

// ---------- Reglas propias (spec 3.0, §5.2): se validan enteras, se prueban y luego se activan ----------
const rulesFile = $('#rules-file');
const rulesPanelBox = $('#rules-panel');
const rulesStatus = $('#rules-status');
const rulesLoad = $('#rules-load');
let pendingRules = null;

/** Análisis guardados para la vista previa (vacío con el historial apagado). */
async function savedEntries() {
  if (!historyControl.enabled() || !(await historyControl.ensure())) return [];
  const h = historyControl.history();
  return h ? (await h.list({ limit: HISTORY_MAX }).catch(() => ({ items: [] }))).items : [];
}

function paintRules(model, focus = false) {
  rulesPanelBox.replaceChildren(rulesPanel(model));
  if (focus) rulesPanelBox.querySelector('[tabindex="-1"]')?.focus();
}

async function showActiveRules(focus = false) {
  const rules = state.rules?.rules ?? [];
  if (!rules.length) return paintRules({ state: 'empty' }, focus);
  return paintRules({ state: 'active', rules, preview: previewRules(rules, await savedEntries()) }, focus);
}

/** Con reglas nuevas, el análisis abierto se rehace si su texto sigue en memoria (decisión 4 del plan). */
function rerunWithRules() {
  if (!state.lastReport || !state.lastInput || state.saved || state.batch) return;
  state.lastReport = analyzeWith({ ...state.lastInput, ...state.analyst });
  paint();
  historyControl.record(state.lastInput, state.lastReport, state.lastInput.kind === 'eml' ? state.fileName ?? null : null);
}

rulesLoad.addEventListener('click', () => rulesFile.click());
rulesFile.addEventListener('change', async () => {
  const file = rulesFile.files?.[0];
  rulesFile.value = '';
  if (!file) return;
  pendingRules = null;
  show(rulesStatus, null);
  let res;
  let text = '';
  if ((file.size ?? 0) > RULES_LIMITS.fileBytes) res = { ok: false, errors: [{ rule: null, path: '', reason: t('app.rules.tooBig') }] };
  else {
    try {
      text = await file.text();
      res = validateRules(text);
    } catch {
      res = { ok: false, errors: [{ rule: null, path: '', reason: t('app.rules.unreadable') }] };
    }
  }
  if (!res.ok) return paintRules({ state: 'errors', errors: res.errors.map(formatRuleError) }, true);
  // Se guarda el mismo texto que se ha validado (leerlo otra vez podría dar otro si el fichero cambia).
  pendingRules = { source: text, rules: res.rules };
  return paintRules({ state: 'preview', rules: res.rules, preview: previewRules(res.rules, await savedEntries()) }, true);
});
rulesPanelBox.addEventListener('click', async (e) => {
  const action = e.target.closest?.('[data-action]')?.dataset.action;
  if (action === 'rules-activate' && pendingRules) {
    state.rules = pendingRules;
    pendingRules = null;
    const saved = await historyControl.saveRules(state.rules.source);
    say(rulesStatus, saved ? 'app.rules.activeSaved' : 'app.rules.active', { count: state.rules.rules.length });
    await showActiveRules(true);
    rerunWithRules();
  } else if (action === 'rules-discard') {
    pendingRules = null;
    say(rulesStatus, 'app.rules.discarded');
    await showActiveRules();
    rulesLoad.focus();
  } else if (action === 'rules-remove') {
    state.rules = null;
    await historyControl.clearRules();
    say(rulesStatus, 'app.rules.removed');
    await showActiveRules();
    rulesLoad.focus();
    rerunWithRules();
  }
});

const DAY = 24 * 60 * 60 * 1000;
/** Lee del historial lo que pinta la vista y la vuelve a pintar. */
async function refreshHistory(extra = {}) {
  const h = historyControl.history();
  if (!h) {
    state.historyData = null;
    paint();
    return;
  }
  const { filters, offset } = state.historyQuery;
  try {
    const since = filters.range ? new Date(Date.now() - Number(filters.range) * DAY) : undefined;
    const page = await h.list({ level: filters.level || undefined, technique: filters.technique || undefined, since, offset });
    const all = await h.list({ limit: 500 });
    const techniques = [...new Set(all.items.flatMap((e) => (e.report.techniques ?? []).map((t) => t.id)))].sort();
    const previous = state.historyData ?? {};
    state.historyData = {
      page: { ...page, offset }, totalAll: all.total, filters, techniques,
      search: 'search' in extra ? extra.search : previous.search ?? null,
      compare: 'compare' in extra ? extra.compare : previous.compare ?? null,
      selected: (previous.selected ?? []).filter((id) => page.items.some((e) => e.id === id) || all.items.some((e) => e.id === id)),
      importResult: extra.importResult ?? null,
    };
  } catch {
    state.historyData = null;
  }
  paint();
}

/** Abre el historial desde la portada, con el último análisis guardado como informe de fondo. */
async function openHistory() {
  const h = historyControl.history();
  const latest = h ? (await h.list({ limit: 1 }).catch(() => ({ items: [] }))).items[0] : null;
  if (!latest) return;
  if (!state.lastReport) openSaved(latest, false);
  reportBox.hidden = false;
  location.hash = formatRoute({ mode: 'analyst', view: 'historial' });
  if (state.route.view === 'historial') await refreshHistory();
  reportBox.scrollIntoView({ block: 'start' });
}
historyOpen.addEventListener('click', openHistory);

/** Carga una entrada guardada como informe actual (sin el correo: no se puede reanalizar). */
function openSaved(entry, go = true) {
  cancelBatch();
  state.batch = null;
  state.analyst = {};
  state.lastInput = null;
  state.lastReport = entry.report;
  state.saved = entry;
  state.notes = entry.notes ?? '';
  state.savedNote = () => t('app.savedNote', { date: fmtDate(new Date(entry.savedAt), { dateStyle: 'long', timeStyle: 'short' }) });
  if (go) {
    state.route = { mode: 'analyst', view: 'resumen' };
    if (location.hash !== '#analista') history.pushState(null, '', '#analista');
    paint();
    focusView();
  }
}

async function historyAction(action, target) {
  if (action === 'history-enable') {
    historyToggle.checked = true;
    const res = await historyControl.enable();
    if (res.ok) say(historyStatus, 'app.history.on');
    await refreshDashboard();
    return reportBox.querySelector('.view__title')?.focus();
  }
  await historyControl.ensure();
  const h = historyControl.history();
  if (!h) return;
  const id = target.getAttribute('data-id');
  if (action === 'history-open') {
    const entry = await h.get(id).catch(() => null);
    if (!entry) {
      announce(t('app.history.gone'));
      return refreshHistory();
    }
    return openSaved(entry);
  }
  if (action === 'history-delete') {
    await h.remove(id).catch(() => {});
    announce(t('app.history.deleted'));
    await refreshHistory();
    updateHistoryButton();
    return reportBox.querySelector('[data-action="history-export"]')?.focus();
  }
  if (action === 'history-page') {
    state.historyQuery.offset = Number(target.getAttribute('data-offset')) || 0;
    await refreshHistory();
    return reportBox.querySelector('.history__table')?.focus();
  }
  if (action === 'history-search') {
    const query = reportBox.querySelector('[data-role="history-query"]')?.value ?? '';
    const results = await h.searchIoc(query).catch(() => []);
    await refreshHistory({ search: { query, results } });
    announce(searchMessage(results.length));
    return reportBox.querySelector('[data-role="history-query"]')?.focus();
  }
  if (action === 'history-compare') {
    const [a, b] = state.historyData?.selected ?? [];
    const compare = a && b ? await h.compare(a, b).catch(() => null) : null;
    await refreshHistory({ compare });
    return reportBox.querySelector('.history__compare h3')?.focus?.();
  }
  if (action === 'history-clear') return reportBox.querySelector('.history__dialog')?.showModal();
  if (action === 'history-clear-cancel') {
    reportBox.querySelector('.history__dialog')?.close();
    return reportBox.querySelector('[data-action="history-clear"]')?.focus();
  }
  if (action === 'history-clear-confirm') {
    reportBox.querySelector('.history__dialog')?.close();
    // Borra la base entera; si el historial sigue encendido, el siguiente análisis la vuelve a crear.
    await historyControl.clear().catch(() => {});
    // Las reglas propias vivían en la misma base: se van con ella.
    const hadRules = Boolean(state.rules);
    state.rules = null;
    if (hadRules) say(rulesStatus, 'app.rules.removed');
    showActiveRules();
    state.historyData = null;
    state.historyQuery = { filters: {}, offset: 0 };
    await refreshHistory();
    updateHistoryButton();
    announce(hadRules ? t('app.history.clearedRules') : t('app.history.cleared'));
    return reportBox.querySelector('.view__title')?.focus();
  }
  if (action === 'history-export') {
    download(await h.exportJson(), 'historial');
    return announce(t('app.history.exported'));
  }
  if (action === 'history-import') return historyImport.click();
  return undefined;
}

const historyImport = document.createElement('input');
historyImport.type = 'file';
historyImport.accept = '.json,application/json';
historyImport.hidden = true;
document.body.append(historyImport);
historyImport.addEventListener('change', async () => {
  const file = historyImport.files?.[0];
  historyImport.value = '';
  await historyControl.ensure();
  const h = historyControl.history();
  if (!file || !h) return;
  let importResult;
  try {
    if (file.size > 20 * 1024 * 1024) throw new Error(t('app.history.importTooBig'));
    importResult = await h.importJson(await file.text());
  } catch (e) {
    importResult = { imported: 0, rejected: [{ index: -1, error: e.message }] };
  }
  await refreshHistory({ importResult });
  updateHistoryButton();
  announce(`${t('history.import.result', { imported: importResult.imported, rejected: importResult.rejected.length })}.`);
});

state.route = { mode: initialMode(storage((s) => s), location.hash), view: parseRoute(location.hash).view };
// El modo recordado se lleva a la URL, para que Atrás y los enlaces copiados digan lo mismo que la pantalla.
if (state.route.mode === 'analyst' && !isAnalystHash(location.hash) && (location.hash === '' || location.hash === '#')) {
  history.replaceState(null, '', formatRoute(state.route));
}

const savedTheme = storage((s) => s.getItem('phishlens-theme'));
if (savedTheme === 'light' || savedTheme === 'dark') document.documentElement.dataset.theme = savedTheme;

$('#theme-toggle').addEventListener('click', () => {
  const current = document.documentElement.dataset.theme
    ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  storage((s) => s.setItem('phishlens-theme', next));
});

// ---------- Idioma (spec 3.1): ES / EN sin volver a analizar ----------
const langToggle = $('#lang-toggle');
function paintLangToggle() {
  // Texto visible «EN» y, para el lector de pantalla, «· Switch to English» en el idioma de destino:
  // el nombre accesible empieza por lo que se ve (WCAG 2.5.3).
  const hint = document.createElement('span');
  hint.className = 'visually-hidden';
  hint.textContent = ` · ${t('topbar.lang.to')}`;
  langToggle.replaceChildren(t('topbar.lang.short'), hint);
  langToggle.setAttribute('lang', t('topbar.lang.target'));
}
/**
 * Vuelve a pintar todo lo visible en el idioma activo con lo que ya hay en memoria: nunca vuelve a
 * analizar ni guarda nada en el historial (spec 3.1). Las notas forenses viven en state.notes.
 */
function rerender() {
  translatePage(document);
  paintLangToggle();
  for (const [node, text] of live) node.textContent = text();
  showActiveRules();
  if (state.lastReport && !reportBox.hidden) paint();
}
// El idioma de arranque se pone antes de escuchar cambios: así se pinta una vez y sin aviso.
setLang(initialLang(storage((s) => s.getItem(LANG_KEY)), navigator.language));
rerender();
onLangChange(() => {
  rerender();
  announce(t('status.lang'));
});
langToggle.addEventListener('click', () => {
  setLang(getLang() === 'es' ? 'en' : 'es');
  storage((s) => s.setItem(LANG_KEY, getLang()));
  langToggle.focus();
});

// ---------- Pestañas (patrón ARIA tabs) ----------
function activateTab(group, tab, focus = false) {
  for (const t of group) {
    const selected = t === tab;
    t.setAttribute('aria-selected', String(selected));
    t.tabIndex = selected ? 0 : -1;
    document.getElementById(t.getAttribute('aria-controls')).hidden = !selected;
  }
  if (focus) tab.focus();
}

/** Navegación con flechas, Inicio y Fin dentro de un tablist. */
function tabKeydown(e, group, onSelect) {
  const i = group.indexOf(e.target);
  if (i < 0) return;
  const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: group.length - 1 }[e.key];
  if (next === undefined) return;
  e.preventDefault();
  onSelect(group[(next + group.length) % group.length], true);
}

function selectTab(tab, focus = false) {
  activateTab(tabs, tab, focus);
  state.tab = tab.id.replace('tab-', '');
  showError('');
}

for (const tab of tabs) {
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', (e) => tabKeydown(e, tabs, selectTab));
}

// ---------- Errores ----------
/** Error del formulario por su clave (se traduce al cambiar de idioma); sin clave lo quita. */
function showError(key, params) {
  show(errorBox, key ? () => t(key, params) : null);
  errorBox.hidden = !key;
}

// ---------- Fichero ----------

function resetDropzone() {
  dropzone.classList.remove('has-file');
  for (const sel of ['.dropzone__title', '.dropzone__hint']) live.delete(dropzone.querySelector(sel));
  translatePage(dropzone);
}

// Un fichero que no vale muestra el error pero no descarta lo que ya había (ni el lote).
async function loadFile(file) {
  showError('');
  if (!file) return;
  if (file.size > MAX_BYTES) {
    showError('app.error.fileSize', { size: decimal((file.size / 1024 / 1024).toFixed(1)), max: MAX_MB });
    return;
  }
  if (!/\.(eml|txt)$/i.test(file.name) && file.type !== 'message/rfc822') {
    showError('app.error.fileType');
    return;
  }
  let text;
  let bytes;
  try {
    // Los bytes van al informe forense: sus hashes son los del fichero (BOM, Latin-1) y no los del texto.
    bytes = new Uint8Array(await file.arrayBuffer());
    text = new TextDecoder().decode(bytes);
  } catch {
    showError('app.error.fileRead');
    return;
  }
  cancelBatch();
  state.fileText = text;
  state.fileName = file.name;
  state.fileBytes = bytes;
  dropzone.classList.add('has-file');
  show(dropzone.querySelector('.dropzone__title'), () => file.name);
  say(dropzone.querySelector('.dropzone__hint'), 'app.drop.ready', { size: decimal((file.size / 1024).toFixed(1)) });
  run();
}

fileInput.addEventListener('change', () => loadFiles([...fileInput.files]));

// Se puede soltar el archivo en cualquier parte de la página.
const overlay = $('#drop-overlay');
let dragDepth = 0;
const hasFiles = (e) => [...(e.dataTransfer?.types ?? [])].includes('Files');
window.addEventListener('dragenter', (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth++;
  overlay.hidden = false;
  dropzone.classList.add('is-over');
});
window.addEventListener('dragover', (e) => hasFiles(e) && e.preventDefault());
window.addEventListener('dragleave', (e) => {
  if (!hasFiles(e)) return;
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) {
    overlay.hidden = true;
    dropzone.classList.remove('is-over');
  }
});
window.addEventListener('drop', (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth = 0;
  overlay.hidden = true;
  dropzone.classList.remove('is-over');
  selectTab($('#tab-eml'));
  loadFiles([...e.dataTransfer.files]);
});

// ---------- Lote: varios correos a la vez ----------
const batchStatus = $('#batch-status');
const batchProgress = $('#batch-progress');
const batchProgressText = $('#batch-progress-text');
const batchNotice = $('#batch-notice');

const SKIP_REASONS = new Set(['tipo', 'tamano', 'vacio', 'limite', 'duplicado', 'error']);
const skipReason = (r) => t(`app.skip.${SKIP_REASONS.has(r) ? r : 'error'}`, { max: MAX_MB });

/** Descarta el lote en curso (si lo hay) y el que se estaba viendo. */
function cancelBatch() {
  if (state.batch || state.batchAbort) resetDropzone();
  state.batchAbort?.abort();
  state.batchAbort = null;
  state.batch = null;
  state.campaign = null;
  state.batchTexts = new Map();
  batchStatus.hidden = true;
  batchNotice.hidden = true;
  batchNotice.replaceChildren();
}

function showBatchNotice(warning, skipped) {
  batchNotice.replaceChildren();
  if (warning) {
    const p = document.createElement('p');
    p.textContent = warning;
    batchNotice.append(p);
  }
  if (skipped.length) {
    const title = document.createElement('p');
    say(title, 'app.skip.title', { count: skipped.length });
    const list = document.createElement('ul');
    for (const s of skipped) {
      const li = document.createElement('li');
      show(li, () => reveal(`${s.name}: ${skipReason(s.reason)}`));
      list.append(li);
    }
    batchNotice.append(title, list);
  }
  batchNotice.hidden = !warning && !skipped.length;
}

/** Abre un correo del lote (por su clave) sin perder el modo ni la vista. */
function openBatchEmail(key) {
  const entry = state.batch?.entries.find((e) => e.key === key);
  if (!entry) return;
  state.batch.current = key;
  state.analyst = {};
  state.lastReport = entry.report;
  state.savedNote = '';
  state.saved = null;
  state.notes = '';
  state.lastInput = { kind: 'eml', value: state.batchTexts.get(key) ?? '' };
}

/** Analiza varios ficheros {name, size, text()} como un lote. */
async function runBatch(files) {
  cancelBatch();
  showError('');
  // El correo suelto de antes ya no es lo que se ve: «Analizar» no debe volver a él.
  state.fileText = null;
  state.fileBytes = null;
  const controller = new AbortController();
  state.batchAbort = controller;
  const texts = new Map();
  batchStatus.hidden = false;
  batchProgress.max = files.length;
  batchProgress.value = 0;
  say(batchProgressText, 'app.batch.progress', { i: 0, n: files.length });
  const out = await analyzeBatch(files, {
    signal: controller.signal,
    analyze: (input) => {
      const report = analyzeWith(input);
      texts.set(report, input.value);
      return report;
    },
    onProgress: (i, n) => {
      if (controller.signal.aborted) return;
      batchProgress.max = n;
      batchProgress.value = i;
      // La barra avanza con cada correo, pero el texto (que lee el lector de pantalla) solo cada 10.
      if (i % 10 === 0 && i < n) say(batchProgressText, 'app.batch.progress', { i, n });
    },
  });
  // Otro análisis empezó mientras tanto: este lote ya no pinta nada.
  if (!out || controller.signal.aborted || state.batchAbort !== controller) return;
  state.batchAbort = null;
  const done = out.entries.length;
  const skippedCount = out.skipped.length;
  show(batchProgressText, () => [t('app.batch.done', { count: done }), skippedCount ? t('app.batch.skipped', { count: skippedCount }) : null].filter(Boolean).join(' '));
  showBatchNotice(out.warning, out.skipped);
  if (!out.entries.length) {
    batchStatus.hidden = !out.skipped.length && !out.warning;
    showError('app.error.batchNone');
    return;
  }
  try {
    state.batchTexts = new Map(out.entries.map((e) => [e.key, texts.get(e.report)]));
    // Se empieza por el primero por nombre, el mismo orden que el selector.
    const first = [...out.entries].sort((a, b) => String(a.name).localeCompare(String(b.name), LOCALE[getLang()]))[0];
    state.batch = { ...out, graph: buildGraph(out.entries), campaigns: findCampaigns(out.entries), current: first.key };
    state.analyzedAt = new Date();
    openBatchEmail(first.key);
  } catch {
    // Un lote raro nunca debe dejar la página a medias.
    cancelBatch();
    showError('app.error.batchGraph');
    return;
  }
  dropzone.classList.add('has-file');
  say(dropzone.querySelector('.dropzone__title'), 'campaigns.emails.count', { count: done });
  say(dropzone.querySelector('.dropzone__hint'), 'app.drop.batch');
  paint();
  historyControl.recordBatch(state.batch, state.batchTexts);
  announce(t('app.batch.announce', { emails: t('campaigns.emails.count', { count: done }), campaigns: t('app.campaigns.count', { count: state.batch.campaigns.length }), headline: state.lastReport.verdict.headline }));
  reportBox.scrollIntoView({ block: 'start' });
}

/** Uno solo: el flujo de siempre. Varios: un lote. */
function loadFiles(files) {
  if (!files.length) return null;
  if (files.length > 1) return runBatch(files);
  return loadFile(files[0]);
}

// ---------- Análisis ----------
function currentInput() {
  if (state.tab === 'eml') return state.fileText == null ? null : { kind: 'eml', value: state.fileText };
  if (state.tab === 'text') return rawInput.value.trim() ? { kind: 'text', value: rawInput.value } : null;
  return urlInput.value.trim() ? { kind: 'url', value: urlInput.value.trim() } : null;
}

function run() {
  const input = currentInput();
  // Con un lote a la vista y sin fichero nuevo, «Analizar» no tiene nada que rehacer: se vuelve al informe.
  if (!input && state.tab === 'eml' && state.batch) {
    showError('');
    reportBox.scrollIntoView({ block: 'start' });
    return;
  }
  if (!input) {
    showError(`app.error.empty.${state.tab}`);
    return;
  }
  if (input.value.length > MAX_BYTES) {
    showError('app.error.textSize', { max: MAX_MB });
    return;
  }
  showError('');
  cancelBatch();
  state.analyst = {};
  try {
    state.lastInput = input;
    state.savedNote = '';
    state.saved = null;
    state.notes = '';
    state.analyzedAt = new Date();
    state.lastReport = analyzeWith(input);
    paint();
    announce(t('app.result', { headline: state.lastReport.verdict.headline, score: state.lastReport.score }));
    historyControl.record(input, state.lastReport, input.kind === 'eml' ? state.fileName ?? null : null);
  } catch {
    // Un email malformado nunca debe dejar la página rota.
    reportBox.hidden = true;
    showError('app.error.analyze');
    return;
  }
  reportBox.scrollIntoView({ block: 'start' });
}

$('#analyze-btn').addEventListener('click', run);
urlInput.addEventListener('keydown', (e) => e.key === 'Enter' && run());
rawInput.addEventListener('keydown', (e) => (e.ctrlKey || e.metaKey) && e.key === 'Enter' && run());

// ---------- Acciones y pestañas del informe (delegación de eventos) ----------
function toast(message) {
  const box = document.createElement('div');
  box.className = 'toast';
  box.setAttribute('role', 'status');
  box.textContent = message;
  document.body.append(box);
  setTimeout(() => box.remove(), 2400);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(t('app.copy.ok'));
  } catch {
    toast(t('app.copy.blocked'));
  }
}

/** Aviso corto para el lector de pantalla (se vacía antes para que repita aunque el texto coincida). */
function announce(text) {
  const box = $('#report-status');
  box.textContent = '';
  setTimeout(() => { box.textContent = text; }, 50);
}

// ---------- Modo y vista del informe (la URL manda: '' sencillo, #analista/<vista> analista) ----------
function paint(options = {}) {
  if (!state.lastReport) return;
  const { mode } = state.route;
  const context = { batch: state.batch, historyEnabled: historyControl.enabled() };
  const view = resolveView(state.route.view, state.lastReport, context);
  renderReport(reportBox, state.lastReport, {
    mode, view, ...context, campaign: state.campaign, history: state.historyData, dashboard: state.dashboard, savedNote: state.savedNote ? state.savedNote() : '', ...options,
  });
  // En móvil la navegación es una fila con desplazamiento: la vista actual tiene que verse.
  const nav = reportBox.querySelector('.nav-rail');
  const current = nav?.querySelector('[aria-current="page"]');
  if (nav && current && nav.scrollWidth > nav.clientWidth) {
    const offset = current.getBoundingClientRect().left - nav.getBoundingClientRect().left;
    nav.scrollLeft += offset - (nav.clientWidth - current.offsetWidth) / 2;
  }
}

/** Lleva el foco al título de la vista nueva, para que teclado y lector de pantalla sepan dónde están. */
function focusView() {
  const heading = reportBox.querySelector('.view__title, .verdict-card__headline');
  if (!heading) return;
  if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1');
  heading.focus({ preventScroll: true });
  heading.scrollIntoView({ block: 'nearest' });
}

function onRoute() {
  const hash = location.hash;
  // Un enlace de la página (#como-funciona, #privacidad) no cambia el informe.
  if (hash && hash !== '#' && !isAnalystHash(hash)) return;
  state.route = parseRoute(hash);
  storage((s) => s.setItem(MODE_KEY, state.route.mode));
  if (!state.lastReport || reportBox.hidden) return;
  if (state.route.view === 'historial') {
    refreshHistory().then(focusView);
    return;
  }
  if (state.route.view === 'panel') {
    refreshDashboard().then(focusView);
    return;
  }
  paint();
  focusView();
}

/** Recalcula el panel solo si cambió el historial (dashboard-data.js memoriza por revisión). */
async function refreshDashboard() {
  state.dashboard = await dashboardData(historyControl, state.dashboardCache).catch(() => null);
  paint();
}

async function dashboardAction(action, target) {
  if (action === 'dashboard-search') {
    const query = target.getAttribute('data-ioc') ?? '';
    const h = historyControl.history();
    const results = h ? await h.searchIoc(query).catch(() => []) : [];
    state.route = { mode: 'analyst', view: 'historial' };
    history.pushState(null, '', formatRoute(state.route));
    await refreshHistory({ search: { query, results } });
    announce(searchMessage(results.length));
    return reportBox.querySelector('[data-role="history-query"]')?.focus();
  }
  if (action === 'dashboard-open') {
    const h = historyControl.history();
    const entry = h ? await h.findBySha256(target.getAttribute('data-sha')).catch(() => null) : null;
    if (!entry) {
      announce(t('app.history.gone'));
      return refreshDashboard();
    }
    return openSaved(entry);
  }
  return undefined;
}
window.addEventListener('hashchange', onRoute);

/** Cambia de modo: el modo analista vuelve a la última vista abierta. */
function goTo(mode) {
  if (mode === state.route.mode) return;
  const next = formatRoute({ mode, view: state.route.view });
  if (next) {
    location.hash = next;
  } else {
    // Volver al sencillo sin '#': pushState no dispara hashchange, así que se avisa a mano.
    history.pushState(null, '', location.pathname + location.search);
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  }
}

reportBox.addEventListener('click', onReportAction);
reportBox.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && e.target.getAttribute?.('data-role') === 'history-query') {
    e.preventDefault();
    historyAction('history-search', e.target);
  }
});
// ---------- Grafo de IOCs: un paso de Tab y flechas entre nodos ----------
reportBox.addEventListener('keydown', (e) => {
  const node = e.target.closest?.('.graph__node');
  if (!node) return;
  const nodes = [...node.ownerSVGElement.querySelectorAll('.graph__node')];
  const next = graphKey(nodes.indexOf(node), e.key, nodes.length);
  if (next == null) return;
  e.preventDefault();
  node.setAttribute('tabindex', '-1');
  nodes[next].setAttribute('tabindex', '0');
  nodes[next].focus();
});
reportBox.addEventListener('focusin', (e) => {
  const node = e.target.closest?.('.graph__node');
  if (!node) return;
  const svgRoot = node.ownerSVGElement;
  for (const x of svgRoot.querySelectorAll('.is-related')) x.classList.remove('is-related');
  const id = node.dataset.node;
  const related = new Set([id]);
  for (const line of svgRoot.querySelectorAll('.graph__edge')) {
    if (line.dataset.from !== id && line.dataset.to !== id) continue;
    line.classList.add('is-related');
    related.add(line.dataset.from);
    related.add(line.dataset.to);
  }
  for (const g of svgRoot.querySelectorAll('.graph__node')) if (related.has(g.dataset.node)) g.classList.add('is-related');
  svgRoot.classList.add('has-focus');
});
reportBox.addEventListener('focusout', (e) => {
  const svgRoot = e.target.closest?.('.graph__node')?.ownerSVGElement;
  if (!svgRoot || svgRoot.contains(e.relatedTarget)) return;
  svgRoot.classList.remove('has-focus');
  for (const x of svgRoot.querySelectorAll('.is-related')) x.classList.remove('is-related');
});

reportBox.addEventListener('change', (e) => {
  const action = e.target.getAttribute?.('data-action');
  if (action === 'history-filter') {
    state.historyQuery = { filters: { ...state.historyQuery.filters, [e.target.getAttribute('data-filter')]: e.target.value }, offset: 0 };
    const name = e.target.getAttribute('data-filter');
    refreshHistory().then(() => reportBox.querySelector(`[data-filter="${name}"]`)?.focus());
    return;
  }
  if (action === 'history-select' && state.historyData) {
    const id = e.target.getAttribute('data-id');
    const set = new Set(state.historyData.selected);
    if (e.target.checked) set.add(id);
    else set.delete(id);
    // Como mucho dos: el más antiguo marcado se desmarca.
    state.historyData.selected = [...set].slice(-2);
    paint();
    reportBox.querySelector(`[data-action="history-select"][data-id="${id}"]`)?.focus();
    return;
  }
  if (e.target.id !== 'batch-email') return;
  openBatchEmail(e.target.value);
  paint();
  const select = $('#batch-email');
  select?.focus();
  announce(t('app.batch.email', { headline: state.lastReport.verdict.headline, score: state.lastReport.score }));
});

// ---------- Menús (patrón ARIA menu button) ----------
const menuItems = (menu) => [...menu.querySelectorAll('[role="menuitem"]')];

function closeMenu(root, focusTrigger = false) {
  const trigger = root.querySelector('[aria-haspopup="menu"]');
  const menu = root.querySelector('[role="menu"]');
  if (!menu || menu.hidden) return;
  menu.hidden = true;
  trigger.setAttribute('aria-expanded', 'false');
  if (focusTrigger) trigger.focus();
}

function openMenu(root, last = false) {
  const trigger = root.querySelector('[aria-haspopup="menu"]');
  const menu = root.querySelector('[role="menu"]');
  menu.hidden = false;
  trigger.setAttribute('aria-expanded', 'true');
  const items = menuItems(menu);
  items[last ? items.length - 1 : 0]?.focus();
}

const closeAllMenus = (except) => {
  for (const root of document.querySelectorAll('.menu-button')) if (root !== except) closeMenu(root);
};

document.addEventListener('click', (e) => {
  const root = e.target.closest('.menu-button');
  const trigger = e.target.closest('[aria-haspopup="menu"]');
  closeAllMenus(root);
  if (!root) return;
  if (trigger) {
    if (trigger.getAttribute('aria-expanded') === 'true') closeMenu(root);
    else openMenu(root);
  } else if (e.target.closest('[role="menuitem"]')) {
    closeMenu(root, true);
  }
});

document.addEventListener('keydown', (e) => {
  const root = e.target.closest?.('.menu-button');
  if (!root) return;
  if (e.target.matches('[aria-haspopup="menu"]') && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
    e.preventDefault();
    openMenu(root, e.key === 'ArrowUp');
    return;
  }
  if (!e.target.matches('[role="menuitem"]')) return;
  const items = menuItems(root);
  const move = menuKey(items.indexOf(e.target), e.key, items.length);
  if (!move) return;
  if (move.close) {
    // Tab sigue su camino natural; Escape devuelve el foco al botón.
    if (e.key === 'Escape') e.preventDefault();
    closeMenu(root, e.key === 'Escape');
    return;
  }
  e.preventDefault();
  items[move.index].focus();
});

// Al imprimir se abren los «¿Por qué?» del informe (no el formulario de DKIM/SPF) y luego se dejan como estaban.
let openedForPrint = [];
window.addEventListener('beforeprint', () => {
  // Al imprimir (botón o Ctrl+P) siempre sale el informe forense, se esté en el modo que se esté.
  reportBox.querySelector(':scope > .forensic')?.remove();
  if (state.lastReport && !reportBox.hidden) {
    const doc = forensicDoc();
    reportBox.append(renderForensic(doc));
    // El pie de cada hoja (@page) lee el hash de esta variable; solo puede ser hexadecimal.
    const sha = /^[0-9a-f]{64}$/.test(doc.identification.sha256 ?? '') ? doc.identification.sha256 : t('forensic.unavailable');
    document.documentElement.style.setProperty('--forensic-sha', `"${sha}"`);
  }
  openedForPrint = [...reportBox.querySelectorAll('details:not([open]):not(.auth-local)')];
  for (const d of openedForPrint) d.open = true;
});
window.addEventListener('afterprint', () => {
  for (const d of openedForPrint) d.open = false;
  openedForPrint = [];
  reportBox.querySelector(':scope > .forensic')?.remove();
  document.documentElement.style.removeProperty('--forensic-sha');
});

// ---------- Comprobación local de DKIM y SPF ----------
const authLive = $('#auth-live');

/** Re-analiza con lo que ha pegado el analista y vuelve a abrir la pestaña de autenticación. */
function reanalyze(status) {
  if (!state.lastInput) {
    authLive.textContent = t('app.auth.saved');
    return;
  }
  state.lastReport = analyzeWith({ ...state.lastInput, ...state.analyst });
  historyControl.record(state.lastInput, state.lastReport, state.batch?.entries.find((e) => e.key === state.batch.current)?.name ?? state.fileName ?? null);
  const dkimKey = $('#dkim-key')?.value ?? '';
  const spfRecord = $('#spf-record')?.value ?? '';
  state.route = { mode: 'analyst', view: 'autenticacion' };
  paint({ authStatus: status, dkimKey, spfRecord });
  authLive.textContent = '';
  // Se vacía y se rellena para que el lector de pantalla lo anuncie aunque el texto se repita.
  setTimeout(() => { authLive.textContent = status; }, 50);
  focusView();
}

async function verifyDkim() {
  if (!state.lastInput) return reanalyze('');
  const key = $('#dkim-key')?.value.trim();
  if (!key) return reanalyze(t('app.auth.dkimMissing'));
  const input = state.lastInput;
  try {
    const dkim = await verifyDkimForInput(input, key);
    // Si mientras tanto se analizó otro correo, este resultado ya no es suyo.
    if (state.lastInput !== input) return;
    state.analyst = { ...state.analyst, dkim };
    reanalyze(`DKIM: ${dkim.reason}.`);
  } catch {
    if (state.lastInput !== input) return;
    reanalyze(t('app.auth.dkimFailed'));
  }
}

function evalSpf() {
  const spfRecord = $('#spf-record')?.value.trim();
  if (!spfRecord) return reanalyze(t('app.auth.spfMissing'));
  state.analyst = { ...state.analyst, spfRecord };
  const { spf } = analyzeInput({ ...state.lastInput, ...state.analyst }).auth;
  reanalyze(spf.state === 'verified' ? `SPF: ${spf.result}.` : `SPF: ${spf.detail}`);
}

function onReportAction(e) {
  const action = e.target.closest('[data-action]')?.dataset.action;
  if (action?.startsWith('history-') && action !== 'history-select' && action !== 'history-filter') {
    historyAction(action, e.target.closest('[data-action]'));
    return;
  }
  if (action?.startsWith('dashboard-')) {
    dashboardAction(action, e.target.closest('[data-action]'));
    return;
  }
  if (action === 'mode-simple') goTo('simple');
  if (action === 'mode-analyst') goTo('analyst');
  if (action === 'pick-campaign') {
    state.campaign = e.target.closest('[data-action]').dataset.id;
    paint();
    reportBox.querySelector('.campaign__title')?.focus({ preventScroll: true });
  }
  if (action === 'view-campaign') {
    state.campaign = e.target.closest('[data-action]').dataset.id;
    location.hash = formatRoute({ mode: 'analyst', view: 'campanas' });
  }
  if (action === 'pick-email') {
    openBatchEmail(e.target.closest('[data-action]').dataset.key);
    state.route = { ...state.route, view: 'resumen' };
    if (state.route.mode === 'analyst' && location.hash !== '#analista') history.pushState(null, '', '#analista');
    paint();
    focusView();
  }
  if (action === 'verify-dkim') verifyDkim();
  if (action === 'eval-spf') evalSpf();
  if (action === 'copy-iocs') copyText(iocsToText(state.lastReport.iocs) || t('forensic.iocs.none'));
  if (action === 'forensic') openForensic();
  if (action === 'export-json') download(reportToJson(state.lastReport), 'informe');
  if (action === 'export-stix') {
    // Con un lote se exporta el lote entero con sus campañas; si no, lo que está abierto.
    const entries = state.batch?.entries ?? [{ key: 'actual', name: 'actual', report: state.lastReport }];
    const { json, count } = stixJson(entries, { campaigns: state.batch?.campaigns ?? [] });
    download(json, 'stix');
    announce(t('app.stix', { count }));
  }
  if (action === 'new') {
    reportBox.hidden = true;
    $('#analizar').scrollIntoView({ block: 'start' });
    tabs.find((t) => t.getAttribute('aria-selected') === 'true').focus();
  }
}

/** Descarga un texto JSON como fichero, sin red (Blob local). */
function download(json, kind, fileName = `phishlens-${kind}-${new Date().toISOString().slice(0, 10)}.json`) {
  const blob = new Blob([json], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = fileName;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ---------- Informe forense ----------
/** De dónde sale el informe abierto: el texto analizado o la entrada del historial. */
function forensicSource() {
  if (state.saved) return { kind: 'saved', name: state.saved.name ?? null, sha256: state.saved.sha256, savedAt: state.saved.savedAt };
  const batchName = state.batch?.entries.find((e) => e.key === state.batch.current)?.name;
  const name = batchName ?? (state.lastInput?.kind === 'eml' ? state.fileName ?? null : null);
  const text = String(state.lastInput?.value ?? '');
  // Solo si lo analizado es el fichero suelto tal cual; si no (lote, texto pegado o editado), el texto.
  const bytes = !batchName && state.lastInput?.kind === 'eml' && state.fileBytes && text === state.fileText ? state.fileBytes : undefined;
  return { kind: 'live', name, text, bytes };
}

function forensicDoc() {
  const analyzedAt = state.saved ? new Date(state.saved.savedAt) : state.analyzedAt ?? new Date();
  return forensicReport({ report: state.lastReport, source: forensicSource(), analyzedAt, version: VERSION, notes: state.notes });
}

const forensicTrigger = () => reportBox.querySelector('[aria-haspopup="menu"]');

async function openForensic() {
  if (!state.lastReport) return;
  // Un correo ya guardado con notas las recupera aunque se haya vuelto a analizar.
  if (!state.notes && !state.saved && historyControl.enabled() && historyControl.history()) {
    const entry = await historyControl.history().findBySha256(sha256(String(state.lastInput?.value ?? ''))).catch(() => null);
    if (entry?.notes) state.notes = entry.notes;
  }
  document.querySelector('dialog.forensic-dialog')?.remove();
  const dialog = forensicDialog({ notes: state.notes });
  document.body.append(dialog);
  const notes = dialog.querySelector('[data-role="forensic-notes"]');
  notes.addEventListener('input', () => {
    state.notes = notes.value;
    dialog.querySelector('[data-role="forensic-count"]').textContent = notesCount(notes.value.length);
  });
  dialog.addEventListener('click', (e) => forensicAction(e.target.closest('[data-action]')?.dataset.action, dialog));
  // Escape o «Cerrar»: el foco vuelve al botón Exportar.
  dialog.addEventListener('close', () => {
    dialog.remove();
    forensicTrigger()?.focus();
  });
  dialog.showModal();
  notes.focus();
}

/** Guarda las notas con el análisis si el historial está encendido. */
async function keepNotes() {
  const sha = state.saved?.sha256 ?? (state.lastInput ? sha256(String(state.lastInput.value ?? '')) : null);
  if (!sha || !historyControl.enabled()) return;
  if (state.saved) state.saved = { ...state.saved, notes: state.notes };
  const message = notesSaveMessage({ enabled: true, ok: await historyControl.saveNotes(sha, state.notes) });
  if (message) announce(message);
}

async function forensicAction(action, dialog) {
  if (action === 'forensic-close') return dialog.close();
  if (action === 'forensic-print') {
    await keepNotes();
    dialog.close();
    return window.print();
  }
  if (action === 'forensic-json') {
    await keepNotes();
    download(forensicJson(forensicDoc()), 'forense', forensicFileName(new Date()));
    return announce(t('app.forensic.json'));
  }
  return undefined;
}

// ---------- Portada: cifras y escala sacadas del código ----------
for (const node of document.querySelectorAll('[data-fact]')) {
  const value = FACTS[node.dataset.fact];
  if (value != null && Object.hasOwn(FACTS, node.dataset.fact)) node.textContent = String(value);
}
const legendBox = document.querySelector('[data-levels]');
if (legendBox) {
  legendBox.replaceChildren(...levelLegend().map((l) => {
    const li = document.createElement('li');
    li.className = `legend__item legend__item--${l.level}`;
    li.textContent = `${l.min}–${l.max} ${l.label}`;
    return li;
  }));
}

// ---------- Ejemplos ----------
const samplesBox = $('#samples');
for (const sample of SAMPLES) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'chip';
  const dot = document.createElement('span');
  dot.className = `chip__dot chip__dot--${sample.id.includes('legitimo') ? 'safe' : 'phishing'}`;
  dot.setAttribute('aria-hidden', 'true');
  btn.append(dot, sample.title);
  // Las muestras van dentro de samples/data.js: la CSP (connect-src 'none') no deja pedirlas por red.
  btn.addEventListener('click', () => {
    rawInput.value = SAMPLE_TEXTS[sample.id];
    selectTab($('#tab-text'));
    run();
  });
  samplesBox.append(btn);
}
for (const lot of BATCHES) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'chip chip--batch';
  btn.textContent = lot.title;
  btn.addEventListener('click', () => {
    selectTab($('#tab-eml'));
    runBatch(lot.files.map((f) => {
      const text = SAMPLE_TEXTS[f];
      return { name: f.split('/').pop(), size: text.length, text: async () => text };
    }));
  });
  samplesBox.append(btn);
}
