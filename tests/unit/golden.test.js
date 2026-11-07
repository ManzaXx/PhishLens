import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildGolden, GOLDEN_PATH } from '../helpers/golden.js';

test('los informes de las muestras no cambian (golden)', () => {
  assert.deepEqual(buildGolden(), JSON.parse(readFileSync(GOLDEN_PATH, 'utf8')));
});

test('ninguna muestra cambia de nivel con las reglas nuevas, y la 13 es peligrosa', () => {
  const levels = Object.fromEntries(Object.entries(buildGolden()).map(([k, v]) => [k, v.level]));
  assert.deepEqual(levels, {
    '01-legitimo-newsletter': 'safe', '02-legitimo-pedido': 'safe', '03-phishing-banco': 'critical', '04-phishing-correos': 'critical',
    '05-phishing-microsoft365': 'critical', '06-phishing-factura-adjunto': 'phishing', '07-phishing-avanzado': 'critical',
    '08-ruta-falsificada': 'critical', '09-cabeceras-trampa': 'phishing', '10-dominio-unicode': 'phishing',
    '11-adjunto-tipo-falso': 'critical', '12-pdf-activo-zip': 'critical', '13-redireccion-anidada': levels['13-redireccion-anidada'],
  });
  assert.ok(['phishing', 'critical'].includes(levels['13-redireccion-anidada']));
  const ids = buildGolden()['13-redireccion-anidada'].findings.map((f) => f.id);
  for (const id of ['links.nested-redirect', 'links.open-redirect', 'links.high-entropy', 'links.non-standard-port']) assert.ok(ids.includes(id), id);
});
