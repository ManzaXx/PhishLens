import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../src/detectors/html.js';

const ids = (html, text = '') => detect({ html, text }).map((f) => `${f.id}:${f.severity}`).sort();

test('formulario dentro del email', () => {
  assert.deepEqual(ids('<form action="https://x.test/p"><input name="pass" type="password"></form>'), ['html.form:high']);
});
test('JavaScript en el email', () => {
  assert.deepEqual(ids('<p>hola</p><script>alert(1)</script>'), ['html.script:high']);
  assert.deepEqual(ids('<p>Mira la factura adjunta, por favor</p><img src="x" onerror="fetch(1)">'), ['html.script:high']);
});
test('URI data: en un enlace', () => {
  assert.deepEqual(ids('<a href="data:text/html;base64,PHNjcmlwdD4=">ver</a>'), ['html.data-uri:high']);
});
test('mucho texto oculto', () => {
  assert.deepEqual(ids(`<div style="display:none">${'palabras legítimas '.repeat(20)}</div><p>Pague ya</p>`), ['html.hidden-text:low']);
});
test('preheader corto oculto es normal', () => {
  assert.deepEqual(ids('<span style="display:none">Novedades de octubre</span><p>Hola</p>'), []);
});
test('email que es solo una imagen', () => {
  assert.deepEqual(ids('<a href="https://x.test"><img src="https://x.test/a.png"></a>'), ['html.image-only:low']);
});
test('HTML normal sin hallazgos', () => {
  assert.deepEqual(ids('<h1>Hola</h1><p>Tu pedido ha salido del almacén y llegará el jueves.</p>'), []);
});
test('sin HTML no opina', () => assert.deepEqual(ids(''), []));
