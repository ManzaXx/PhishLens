// Controlador de la página: entradas, ejemplos, tema y acciones del informe.
import { analyzeInput } from '../engine.js';
import { SAMPLES } from '../../samples/index.js';
import { renderReport, reportToJson } from './render.js';

const MAX_BYTES = 5 * 1024 * 1024;
const $ = (sel) => document.querySelector(sel);

const state = { tab: 'eml', fileText: null, lastReport: null };

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

const savedTheme = storage((s) => s.getItem('phishlens-theme'));
if (savedTheme) document.documentElement.dataset.theme = savedTheme;

$('#theme-toggle').addEventListener('click', () => {
  const current = document.documentElement.dataset.theme
    ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  storage((s) => s.setItem('phishlens-theme', next));
});

// ---------- Pestañas (patrón ARIA tabs) ----------
function selectTab(tab, focus = false) {
  for (const t of tabs) {
    const selected = t === tab;
    t.setAttribute('aria-selected', String(selected));
    t.tabIndex = selected ? 0 : -1;
    document.getElementById(t.getAttribute('aria-controls')).hidden = !selected;
  }
  state.tab = tab.id.replace('tab-', '');
  if (focus) tab.focus();
  showError('');
}

tabs.forEach((tab, i) => {
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', (e) => {
    const delta = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
    if (delta) selectTab(tabs[(i + delta + tabs.length) % tabs.length], true);
    if (e.key === 'Home') selectTab(tabs[0], true);
    if (e.key === 'End') selectTab(tabs.at(-1), true);
  });
});

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
    showError(`El archivo pesa ${(file.size / 1024 / 1024).toFixed(1)} MB. El máximo es 5 MB.`);
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
for (const type of ['dragenter', 'dragover']) {
  dropzone.addEventListener(type, (e) => {
    e.preventDefault();
    dropzone.classList.add('is-over');
  });
}
for (const type of ['dragleave', 'drop']) {
  dropzone.addEventListener(type, () => dropzone.classList.remove('is-over'));
}
dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  loadFile(e.dataTransfer.files[0]);
});

// ---------- Análisis ----------
function currentInput() {
  if (state.tab === 'eml') return state.fileText == null ? null : { kind: 'eml', value: state.fileText };
  if (state.tab === 'text') return rawInput.value.trim() ? { kind: 'text', value: rawInput.value } : null;
  return urlInput.value.trim() ? { kind: 'url', value: urlInput.value.trim() } : null;
}

function run() {
  const input = currentInput();
  if (!input) {
    showError({ eml: 'Elige o arrastra un archivo .eml.', text: 'Pega el contenido del email.', url: 'Escribe una URL.' }[state.tab]);
    return;
  }
  if (input.value.length > MAX_BYTES) {
    showError('El texto supera los 5 MB.');
    return;
  }
  showError('');
  state.lastReport = analyzeInput(input);
  const actions = renderReport(reportBox, state.lastReport);
  actions.addEventListener('click', onReportAction);
  reportBox.scrollIntoView({ block: 'start' });
}

$('#analyze-btn').addEventListener('click', run);
urlInput.addEventListener('keydown', (e) => e.key === 'Enter' && run());
rawInput.addEventListener('keydown', (e) => (e.ctrlKey || e.metaKey) && e.key === 'Enter' && run());

function onReportAction(e) {
  const action = e.target.closest('[data-action]')?.dataset.action;
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
  btn.addEventListener('click', async () => {
    try {
      const res = await fetch(`samples/${sample.file}`);
      if (!res.ok) throw new Error(res.statusText);
      rawInput.value = await res.text();
      selectTab($('#tab-text'));
      run();
    } catch {
      showError('No se pudo cargar el ejemplo. Abre la página desde un servidor (no con file://).');
    }
  });
  samplesBox.append(btn);
}
