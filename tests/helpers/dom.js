// DOM mínimo para probar componentes en Node sin dependencias.
// Solo cubre lo que usan src/ui/dom.js y los componentes; innerHTML lanza a propósito,
// así un componente que intente interpretar HTML falla en los tests.

class Node {
  constructor(document) {
    this.ownerDocument = document;
    this.parentNode = null;
    this.childNodes = [];
  }
}

class Text extends Node {
  constructor(document, data) {
    super(document);
    this.nodeType = 3;
    this.data = String(data);
  }
  get textContent() { return this.data; }
  set textContent(v) { this.data = String(v); }
}

class Element extends Node {
  constructor(document, tagName, namespaceURI = 'http://www.w3.org/1999/xhtml') {
    super(document);
    this.nodeType = 1;
    this.tagName = namespaceURI.endsWith('xhtml') ? tagName.toUpperCase() : tagName;
    this.localName = tagName.toLowerCase();
    this.namespaceURI = namespaceURI;
    this.attributes = new Map();
    this.hidden = false;
    const props = new Map();
    this.style = new Proxy({
      setProperty: (k, v) => props.set(k, String(v)),
      getPropertyValue: (k) => props.get(k) ?? '',
    }, {});
  }

  get children() { return this.childNodes.filter((n) => n.nodeType === 1); }
  get childElementCount() { return this.children.length; }
  get firstElementChild() { return this.children[0] ?? null; }

  get className() { return this.getAttribute('class') ?? ''; }
  set className(v) { this.setAttribute('class', v); }
  get classList() {
    const names = () => this.className.split(/\s+/).filter(Boolean);
    return { contains: (c) => names().includes(c) };
  }
  get dataset() {
    const attr = (k) => `data-${String(k).replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`;
    return new Proxy({}, { get: (_, k) => this.getAttribute(attr(k)) ?? undefined, set: (_, k, v) => { this.setAttribute(attr(k), v); return true; } });
  }
  /** Solo selectores de atributo simples: [data-x]. */
  querySelectorAll(sel) {
    const m = /^\[([\w-]+)\]$/.exec(sel);
    if (!m) throw new Error(`selector no soportado: ${sel}`);
    return findAll(this, (n) => n !== this && n.hasAttribute(m[1]));
  }
  get id() { return this.getAttribute('id') ?? ''; }
  set id(v) { this.setAttribute('id', v); }

  setAttribute(k, v) { this.attributes.set(String(k).toLowerCase(), String(v)); }
  getAttribute(k) { return this.attributes.get(String(k).toLowerCase()) ?? null; }
  hasAttribute(k) { return this.attributes.has(String(k).toLowerCase()); }
  removeAttribute(k) { this.attributes.delete(String(k).toLowerCase()); }

  #adopt(child) {
    const node = typeof child === 'string' ? new Text(this.ownerDocument, child) : child;
    if (node.parentNode) node.parentNode.childNodes = node.parentNode.childNodes.filter((n) => n !== node);
    node.parentNode = this;
    return node;
  }
  append(...nodes) { for (const n of nodes) this.childNodes.push(this.#adopt(n)); }
  appendChild(n) { this.append(n); return n; }
  replaceChildren(...nodes) {
    for (const n of this.childNodes) n.parentNode = null;
    this.childNodes = [];
    this.append(...nodes);
  }

  get textContent() { return this.childNodes.map((n) => n.textContent).join(''); }
  set textContent(v) { this.replaceChildren(...(v === '' || v == null ? [] : [String(v)])); }

  set innerHTML(_) { throw new Error('innerHTML no está permitido'); }
  get innerHTML() { throw new Error('innerHTML no está permitido'); }
  insertAdjacentHTML() { throw new Error('insertAdjacentHTML no está permitido'); }
}

class Document {
  createElement(tag) { return new Element(this, tag); }
  createElementNS(ns, tag) { return new Element(this, tag, ns); }
  createTextNode(data) { return new Text(this, data); }
}

/** Instala un `document` global y devuelve cómo quitarlo. */
export function installDom() {
  const previous = globalThis.document;
  const document = new Document();
  globalThis.document = document;
  return { document, restore() { globalThis.document = previous; } };
}

/** Primer elemento (en profundidad, incluido `node`) que cumple `pred`. */
export function find(node, pred) {
  return findAll(node, pred)[0] ?? null;
}

/** Todos los elementos (en profundidad, incluido `node`) que cumplen `pred`. */
export function findAll(node, pred) {
  const out = [];
  const walk = (n) => {
    if (n.nodeType !== 1) return;
    if (pred(n)) out.push(n);
    for (const c of n.childNodes) walk(c);
  };
  walk(node);
  return out;
}

/** Atajo: predicado por nombre de etiqueta. */
export const tag = (name) => (n) => n.localName === name;
