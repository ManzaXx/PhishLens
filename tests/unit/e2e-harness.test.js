// El arnés de los tests en navegador: sin Chromium se salta con motivo, salvo en CI, donde falla.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { launchOrSkip } from '../e2e/browser.js';

const broken = { chromium: { launch: async () => { throw new Error("Executable doesn't exist at /x/chrome"); } } };
const working = { chromium: { launch: async () => 'navegador' } };

test('sin ejecutable de Chromium y fuera de CI se salta con el motivo', async () => {
  const r = await launchOrSkip(broken, {});
  assert.equal(r.browser, undefined);
  assert.match(r.skip, /Chromium no arranca.*Executable doesn't exist/);
});

test('en CI un Chromium que no arranca es un fallo, no un salto', async () => {
  await assert.rejects(launchOrSkip(broken, { CI: 'true' }), /Executable doesn't exist/);
});

test('con Chromium devuelve el navegador', async () => {
  assert.deepEqual(await launchOrSkip(working, {}), { browser: 'navegador' });
});
