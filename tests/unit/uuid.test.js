// UUIDv5 propio (RFC 9562) con el SHA-1 del proyecto; ids STIX iguales a los de la librería oficial stix2.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { uuidv5 } from '../../src/lib/uuid.js';

test('vector de RFC 9562: www.example.com en el namespace DNS', () => {
  assert.equal(uuidv5('6ba7b810-9dad-11d1-80b4-00c04fd430c8', 'www.example.com'), '2ed6657d-e927-568b-95e1-2665a8aea6a2');
});

test('versión 5, variante RFC y minúsculas; texto Unicode en UTF-8', () => {
  const id = uuidv5('00abedb4-aa42-466c-9c01-fed23315a9b7', '{"value":"pájaro.test"}');
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(id, uuidv5('00abedb4-aa42-466c-9c01-fed23315a9b7', '{"value":"pajaro.test"}'));
  assert.throws(() => uuidv5('no-es-un-uuid', 'x'));
});
