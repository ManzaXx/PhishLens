// Botón de menú «Exportar» (patrón ARIA menu button).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom, find, findAll, tag } from '../helpers/dom.js';

let dom;
let M;
before(async () => {
  dom = installDom();
  M = await import('../../src/ui/components/menu-button.js');
});
after(() => dom.restore());

const ITEMS = [{ action: 'export-json', text: 'Descargar JSON' }, { action: 'copy-iocs', text: 'Copiar IOCs' }, { action: 'print', text: 'Imprimir' }];

test('menuButton: botón con aria-haspopup y menú oculto con elementos menuitem', () => {
  const root = M.menuButton({ label: 'Exportar', items: ITEMS });
  const button = find(root, (n) => n.getAttribute('aria-haspopup') === 'menu');
  assert.equal(button.localName, 'button');
  assert.equal(button.getAttribute('type'), 'button');
  assert.equal(button.getAttribute('aria-expanded'), 'false');
  assert.match(button.textContent, /Exportar/);
  const menu = find(root, (n) => n.getAttribute('role') === 'menu');
  assert.equal(menu.localName, 'ul');
  assert.equal(menu.hidden, true);
  assert.ok(menu.id);
  assert.equal(button.getAttribute('aria-controls'), menu.id);
  assert.equal(menu.getAttribute('aria-labelledby'), button.id);
  assert.ok(findAll(menu, tag('li')).every((li) => li.getAttribute('role') === 'none'));
  const entries = findAll(menu, (n) => n.getAttribute('role') === 'menuitem');
  assert.deepEqual(entries.map((b) => [b.localName, b.getAttribute('data-action'), b.textContent, b.getAttribute('tabindex')]),
    ITEMS.map((i) => ['button', i.action, i.text, '-1']));
});

test('menuKey: flechas circulares, Inicio/Fin y cierre con Escape o Tab', () => {
  assert.deepEqual(M.menuKey(2, 'ArrowDown', 3), { index: 0, close: false });
  assert.deepEqual(M.menuKey(0, 'ArrowDown', 3), { index: 1, close: false });
  assert.deepEqual(M.menuKey(0, 'ArrowUp', 3), { index: 2, close: false });
  assert.deepEqual(M.menuKey(1, 'Home', 3), { index: 0, close: false });
  assert.deepEqual(M.menuKey(1, 'End', 3), { index: 2, close: false });
  assert.deepEqual(M.menuKey(1, 'Escape', 3), { index: 1, close: true });
  assert.deepEqual(M.menuKey(1, 'Tab', 3), { index: 1, close: true });
  assert.equal(M.menuKey(1, 'a', 3), null);
  assert.deepEqual(M.menuKey(-1, 'ArrowDown', 3), { index: 0, close: false });
});
