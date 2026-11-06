// Rutas del informe en la URL (spec 2.3, §2): #analista/<vista>, nunca lanza y nunca sale de la lista.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { VIEWS, NAV_GROUPS, parseRoute, formatRoute, initialMode, resolveView } from '../../src/ui/route.js';

test('vistas y grupos de la navegación', () => {
  assert.deepEqual(VIEWS, ['resumen', 'senales', 'vista-segura', 'autenticacion', 'cabeceras', 'adjuntos', 'iocs', 'attack']);
  assert.deepEqual(NAV_GROUPS.map((g) => g.label), ['Correo', 'Inteligencia']);
  assert.deepEqual(NAV_GROUPS.flatMap((g) => g.views), VIEWS);
  assert.deepEqual(NAV_GROUPS[1].views, ['iocs', 'attack']);
});

test('parseRoute: tabla de casos', () => {
  const S = { mode: 'simple', view: 'resumen' };
  const A = (view = 'resumen') => ({ mode: 'analyst', view });
  const cases = [
    ['', S], ['#', S], ['#como-funciona', S], [undefined, S], [null, S],
    ['#analista', A()], ['#analista/', A()], ['#analista/senales', A('senales')], ['#analista/attack', A('attack')],
    ['#analista/nada', A()], ['#analista/../../x', A()], ['#analista/<img>', A()],
    ['#analista/constructor', A()], ['#analista/__proto__', A()], ['#analista/%E0%A4%A', A()],
    ['#analista/vista%2Dsegura', A('vista-segura')], ['#%E0%A4%A', S], ['#analistas', S],
  ];
  for (const [hash, expected] of cases) assert.deepEqual(parseRoute(hash), expected, String(hash));
});

test('formatRoute y su ida y vuelta', () => {
  assert.equal(formatRoute({ mode: 'simple', view: 'senales' }), '');
  assert.equal(formatRoute({ mode: 'analyst', view: 'resumen' }), '#analista');
  assert.equal(formatRoute({ mode: 'analyst', view: 'iocs' }), '#analista/iocs');
  assert.equal(formatRoute({ mode: 'analyst', view: '<x>' }), '#analista');
  for (const hash of ['', '#analista', '#analista/senales', '#analista/x', '#zzz', '#%E0%A4%A']) {
    const once = formatRoute(parseRoute(hash));
    assert.equal(formatRoute(parseRoute(once)), once, hash);
  }
});

test('initialMode: el hash manda, el almacenamiento sirve de recuerdo y nunca rompe', () => {
  const store = (value) => ({ getItem: () => value });
  const throwing = { getItem() { throw new Error('bloqueado'); } };
  assert.equal(initialMode(throwing, ''), 'simple');
  assert.equal(initialMode(null, ''), 'simple');
  assert.equal(initialMode(store('analyst'), ''), 'analyst');
  assert.equal(initialMode(store('<x>'), ''), 'simple');
  assert.equal(initialMode(store('simple'), '#analista/iocs'), 'analyst');
  assert.equal(initialMode(throwing, '#analista'), 'analyst');
});

test('resolveView: una vista sin contenido en este informe vuelve al resumen', () => {
  const url = { email: { from: null, authResults: null }, findings: [], techniques: [], iocs: {} };
  const eml = { email: { from: { address: 'a@b.test' }, authResults: null }, findings: [], techniques: [], iocs: {} };
  assert.equal(resolveView('autenticacion', url), 'resumen');
  assert.equal(resolveView('cabeceras', url), 'resumen');
  assert.equal(resolveView('senales', url), 'senales');
  assert.equal(resolveView('autenticacion', eml), 'autenticacion');
  assert.equal(resolveView('nada', eml), 'resumen');
  // Adjuntos solo si el correo trae alguno.
  assert.equal(resolveView('adjuntos', eml), 'resumen');
  assert.equal(resolveView('adjuntos', { email: { from: {}, attachments: [{ filename: 'a.pdf' }] } }), 'adjuntos');
});
