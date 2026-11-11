// «Exportar → Descargar STIX 2.1» (spec 2.3, §5.4): en el menú y con un JSON válido.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { installDom } from '../helpers/dom.js';
import { SAMPLE_TEXTS } from '../../samples/data.js';
import { analyzeInput } from '../../src/core/engine.js';
import { validateBundle } from '../../tools/stix-validate.mjs';

let dom;
let M;
before(async () => {
  dom = installDom();
  M = await import('../../src/ui/render.js');
});
after(() => dom.restore());

test('el menú Exportar lleva STIX justo después del JSON', () => {
  assert.deepEqual(M.exportItems().map((i) => [i.action, i.text]), [
    ['export-json', 'Descargar informe (JSON)'], ['export-stix', 'Descargar STIX 2.1'], ['copy-iocs', 'Copiar IOCs'], ['forensic', 'Informe forense'],
  ]);
});

test('stixJson: texto JSON de un bundle válido y el número de objetos', () => {
  const report = analyzeInput({ kind: 'eml', value: SAMPLE_TEXTS['03-phishing-banco'] });
  const { json, count } = M.stixJson([{ key: 'k', name: '03.eml', report }], { now: new Date('2026-11-07T10:00:00.000Z') });
  const bundle = JSON.parse(json);
  assert.deepEqual(validateBundle(bundle), []);
  assert.equal(count, bundle.objects.length);
  assert.ok(json.includes('\n  "objects"'), 'con sangría para leerlo');
});
