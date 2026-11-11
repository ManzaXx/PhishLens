// Traduce el HTML estático de la página (spec 3.1). [data-i18n] cambia su texto; [data-i18n-rich]
// admite un marcado mínimo del diccionario (`código`, **negrita**, _cursiva_, [[tecla]]) que se
// construye con createElement y textContent: nunca innerHTML. [data-i18n-attr="aria-label:clave;…"]
// cambia atributos. El HTML conserva el español para quien no tenga JavaScript.
import { t, getLang } from '../i18n/index.js';

const RICH = /`([^`]+)`|\*\*([^*]+)\*\*|_([^_]+)_|\[\[([^\]]+)\]\]/g;
const TAGS = ['code', 'strong', 'em', 'kbd'];

/** Nodos de un texto con el marcado mínimo: solo code, strong, em y kbd; todo lo demás es texto. */
export function richNodes(doc, text) {
  const out = [];
  let last = 0;
  for (const m of text.matchAll(RICH)) {
    if (m.index > last) out.push(doc.createTextNode(text.slice(last, m.index)));
    const i = [1, 2, 3, 4].find((g) => m[g] != null);
    const node = doc.createElement(TAGS[i - 1]);
    node.textContent = m[i];
    out.push(node);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(doc.createTextNode(text.slice(last)));
  return out;
}

export function translatePage(root) {
  const doc = root.ownerDocument ?? root;
  for (const node of root.querySelectorAll('[data-i18n]')) node.textContent = t(node.dataset.i18n);
  for (const node of root.querySelectorAll('[data-i18n-rich]')) node.replaceChildren(...richNodes(doc, t(node.dataset.i18nRich)));
  for (const node of root.querySelectorAll('[data-i18n-attr]')) {
    for (const pair of node.dataset.i18nAttr.split(';')) {
      const [attr, key] = pair.split(':').map((s) => s.trim());
      if (attr && key) node.setAttribute(attr, t(key));
    }
  }
  if (doc.documentElement) doc.documentElement.lang = getLang();
  if ('title' in doc) doc.title = t('home.title');
  doc.querySelector?.('meta[name="description"]')?.setAttribute('content', t('home.description'));
}
