// translatePage (spec 3.1): textos, marcado mínimo y atributos del HTML estático, sin innerHTML.
import { test, before, after, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { installDom } from '../helpers/dom.js';
import { setLang, _setDictionaries } from '../../src/i18n/index.js';
import { translatePage, richNodes } from '../../src/ui/translate-page.js';

let dom;
before(() => { dom = installDom(); });
after(() => dom.restore());
afterEach(() => { setLang('es'); _setDictionaries(null); });

const DICTS = {
  es: { 'a.t': 'Analizar', 'a.r': 'Pulsa [[⋮]] → _Descargar_ el `.eml` **ya**', 'a.l': 'Tipo de entrada' },
  en: { 'a.t': 'Analyze', 'a.r': 'Press [[⋮]] → _Download_ the `.eml` **now**', 'a.l': 'Input type' },
};

function page() {
  const d = globalThis.document;
  const root = d.createElement('div');
  const b = d.createElement('button'); b.setAttribute('data-i18n', 'a.t'); b.textContent = 'Analizar';
  const p = d.createElement('p'); p.setAttribute('data-i18n-rich', 'a.r');
  const tabs = d.createElement('div'); tabs.setAttribute('data-i18n-attr', 'aria-label:a.l; title:a.t');
  const unknown = d.createElement('span'); unknown.setAttribute('data-i18n', 'no.existe');
  root.append(b, p, tabs, unknown);
  return { root, b, p, tabs, unknown };
}

test('traduce textos, marcado mínimo y atributos', () => {
  _setDictionaries(DICTS);
  setLang('en');
  const { root, b, p, tabs, unknown } = page();
  assert.doesNotThrow(() => translatePage(root));
  assert.equal(b.textContent, 'Analyze');
  assert.equal(p.textContent, 'Press ⋮ → Download the .eml now');
  assert.deepEqual(p.childNodes.filter((n) => n.nodeType === 1).map((n) => [n.localName, n.textContent]),
    [['kbd', '⋮'], ['em', 'Download'], ['code', '.eml'], ['strong', 'now']]);
  assert.equal(tabs.getAttribute('aria-label'), 'Input type');
  assert.equal(tabs.getAttribute('title'), 'Analyze');
  assert.equal(unknown.textContent, 'no.existe');
});

test('el marcado mínimo nunca crea otras etiquetas: <script> sale como texto', () => {
  const nodes = richNodes(globalThis.document, '<script>alert(1)</script> `<b>x</b>`');
  assert.equal(nodes[0].nodeType, 3);
  assert.equal(nodes[0].textContent, '<script>alert(1)</script> ');
  assert.equal(nodes[1].localName, 'code');
  assert.equal(nodes[1].textContent, '<b>x</b>');
});
