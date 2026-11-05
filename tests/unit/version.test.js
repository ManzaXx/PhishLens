// La versión es la misma en package.json, en el JSON exportado y en la primera entrada del CHANGELOG.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

test('versión coherente en package.json, reportToJson y CHANGELOG', () => {
  const { version } = JSON.parse(read('package.json'));
  assert.match(read('src/ui/render.js'), new RegExp(`tool: 'PhishLens', version: '${version.replaceAll('.', '\\.')}'`));
  assert.match(read('CHANGELOG.md'), new RegExp(`^## ${version.replaceAll('.', '\\.')} · \\d{4}-\\d{2}-\\d{2}`, 'm'));
  assert.equal(read('CHANGELOG.md').match(/^## (\S+)/m)[1], version, 'la primera entrada es la versión actual');
});
