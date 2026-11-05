import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../../src/detectors/language.js';

const ids = (text, subject = '') => detect({ subject, text, html: '' }).map((f) => `${f.id}:${f.severity}`).sort();

test('amenaza y urgencia', () => {
  assert.deepEqual(ids('Su cuenta será suspendida en 24 horas.'), ['language.threat:medium', 'language.urgency:medium']);
});
test('pide credenciales', () => assert.deepEqual(ids('Por favor, verifique su contraseña aquí.'), ['language.credentials:high']));
test('premio', () => assert.deepEqual(ids('¡Has ganado un iPhone!'), ['language.prize:medium']));
test('inglés', () => assert.deepEqual(ids('Your account will be locked'), ['language.threat:medium']));
test('asunto también cuenta', () => assert.deepEqual(ids('Hola', 'URGENTE: último aviso'), ['language.urgency:medium']));
test('texto neutro', () => assert.deepEqual(ids('Gracias por tu compra. Tu pedido llegará el jueves.'), []));
test('evidencia con la frase', () => {
  const [f] = detect({ subject: '', text: 'Por favor, verifique su contraseña aquí.', html: '' });
  assert.match(f.evidence, /verifique su contraseña/);
});
test('usa el HTML si no hay texto', () => {
  assert.deepEqual(detect({ subject: '', text: '', html: '<p>Has <b>ganado</b> un premio</p>' }).map((f) => f.id), ['language.prize']);
});
