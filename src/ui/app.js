// Controlador de la página: entradas, ejemplos, tema y acciones del informe.
import { analyzeInput, verifyDkimForInput } from '../core/engine.js';
import { SAMPLES } from '../../samples/index.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { renderReport, reportToJson, iocsToText } from './render.js';
import { parseRoute, formatRoute, initialMode, resolveView, isAnalystHash, MODE_KEY } from './route.js';

import { LIMITS } from '../lib/limits.js';

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
  a.textContent = 'Abre PhishLens en su propia pestaña';
  document.body.append(a);
  throw new Error('PhishLens no se ejecuta dentro de un iframe');
}
const $ = (sel) => document.querySelector(sel);

const state = { tab: 'eml', fileText: null, lastReport: null, lastInput: null, analyst: {}, route: { mode: 'simple', view: 'resumen' } };

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

state.route = { mode: initialMode(storage((s) => s), location.hash), view: parseRoute(location.hash).view };

const savedTheme = storage((s) => s.getItem('phishlens-theme'));
if (savedTheme === 'light' || savedTheme === 'dark') document.documentElement.dataset.theme = savedTheme;

$('#theme-toggle').addEventListener('click', () => {
  const current = document.documentElement.dataset.theme
    ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  storage((s) => s.setItem('phishlens-theme', next));
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
function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

// ---------- Fichero ----------
async function loadFile(file) {
  showError('');
  state.fileText = null;
  if (!file) return;
  if (file.size > MAX_BYTES) {
    showError(`El archivo pesa ${(file.size / 1024 / 1024).toFixed(1)} MB. El máximo es ${MAX_MB} MB.`);
    return;
  }
  if (!/\.(eml|txt)$/i.test(file.name) && file.type !== 'message/rfc822') {
    showError('Solo se aceptan archivos .eml (o .txt con el email original).');
    return;
  }
  state.fileText = await file.text();
  dropzone.classList.add('has-file');
  dropzone.querySelector('.dropzone__title').textContent = file.name;
  dropzone.querySelector('.dropzone__hint').textContent = `${(file.size / 1024).toFixed(1)} KB · listo para analizar`;
  run();
}

fileInput.addEventListener('change', () => loadFile(fileInput.files[0]));

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
  loadFile(e.dataTransfer.files[0]);
});

// ---------- Análisis ----------
function currentInput() {
  if (state.tab === 'eml') return state.fileText == null ? null : { kind: 'eml', value: state.fileText };
  if (state.tab === 'text') return rawInput.value.trim() ? { kind: 'text', value: rawInput.value } : null;
  return urlInput.value.trim() ? { kind: 'url', value: urlInput.value.trim() } : null;
}

function run() {
  state.analyst = {};
  const input = currentInput();
  if (!input) {
    showError({ eml: 'Elige o arrastra un archivo .eml.', text: 'Pega el contenido del email.', url: 'Escribe una URL.' }[state.tab]);
    return;
  }
  if (input.value.length > MAX_BYTES) {
    showError(`El texto supera los ${MAX_MB} MB.`);
    return;
  }
  showError('');
  try {
    state.lastInput = input;
    state.lastReport = analyzeInput(input);
    paint();
  } catch {
    // Un email malformado nunca debe dejar la página rota.
    reportBox.hidden = true;
    showError('No se pudo analizar este contenido. Comprueba que es un email o una URL.');
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
    toast('IOCs copiados al portapapeles');
  } catch {
    toast('No se pudo copiar: tu navegador lo ha bloqueado');
  }
}

// ---------- Modo y vista del informe (la URL manda: '' sencillo, #analista/<vista> analista) ----------
function paint(options = {}) {
  if (!state.lastReport) return;
  const { mode } = state.route;
  const view = resolveView(state.route.view, state.lastReport);
  renderReport(reportBox, state.lastReport, { mode, view, ...options });
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
  paint();
  focusView();
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

// Al imprimir se abren los «¿Por qué?» del informe (no el formulario de DKIM/SPF) y luego se dejan como estaban.
let openedForPrint = [];
window.addEventListener('beforeprint', () => {
  openedForPrint = [...reportBox.querySelectorAll('details:not([open]):not(.auth-local)')];
  for (const d of openedForPrint) d.open = true;
});
window.addEventListener('afterprint', () => {
  for (const d of openedForPrint) d.open = false;
  openedForPrint = [];
});

// ---------- Comprobación local de DKIM y SPF ----------
const authLive = $('#auth-live');

/** Re-analiza con lo que ha pegado el analista y vuelve a abrir la pestaña de autenticación. */
function reanalyze(status) {
  state.lastReport = analyzeInput({ ...state.lastInput, ...state.analyst });
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
  const key = $('#dkim-key')?.value.trim();
  if (!key) return reanalyze('Pega primero la clave pública DKIM.');
  const input = state.lastInput;
  try {
    const dkim = await verifyDkimForInput(input, key);
    // Si mientras tanto se analizó otro correo, este resultado ya no es suyo.
    if (state.lastInput !== input) return;
    state.analyst = { ...state.analyst, dkim };
    reanalyze(`DKIM: ${dkim.reason}.`);
  } catch {
    if (state.lastInput !== input) return;
    reanalyze('DKIM: no se pudo comprobar la firma con esa clave.');
  }
}

function evalSpf() {
  const spfRecord = $('#spf-record')?.value.trim();
  if (!spfRecord) return reanalyze('Pega primero el registro SPF.');
  state.analyst = { ...state.analyst, spfRecord };
  const { spf } = analyzeInput({ ...state.lastInput, ...state.analyst }).auth;
  reanalyze(spf.state === 'verified' ? `SPF: ${spf.result}.` : `SPF: ${spf.detail}`);
}

function onReportAction(e) {
  const action = e.target.closest('[data-action]')?.dataset.action;
  if (action === 'mode-simple') goTo('simple');
  if (action === 'mode-analyst') goTo('analyst');
  if (action === 'verify-dkim') verifyDkim();
  if (action === 'eval-spf') evalSpf();
  if (action === 'copy-iocs') copyText(iocsToText(state.lastReport.iocs) || 'Sin IOCs');
  if (action === 'print') window.print();
  if (action === 'export') {
    const blob = new Blob([reportToJson(state.lastReport)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `phishlens-informe-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  if (action === 'reset') {
    reportBox.hidden = true;
    $('#analizar').scrollIntoView({ block: 'start' });
    tabs.find((t) => t.getAttribute('aria-selected') === 'true').focus();
  }
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
