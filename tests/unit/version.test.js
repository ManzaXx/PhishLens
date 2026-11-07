// La versión es la misma en package.json, en el JSON exportado y en la primera entrada del CHANGELOG.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

test('versión coherente en package.json, reportToJson y CHANGELOG', () => {
  const { version } = JSON.parse(read('package.json'));
  assert.match(read('src/ui/render.js'), new RegExp(`export const VERSION = '${version.replaceAll('.', '\\.')}'`));
  assert.match(read('CHANGELOG.md'), new RegExp(`^## ${version.replaceAll('.', '\\.')} · \\d{4}-\\d{2}-\\d{2}`, 'm'));
  // Una sección «Sin publicar» (lo que lleva main y aún no tiene versión) solo puede ir la primera.
  const headings = [...read('CHANGELOG.md').matchAll(/^## (.+)$/gm)].map((m) => m[1]);
  const released = headings.filter((h) => !h.startsWith('Sin publicar'));
  assert.equal(released[0].split(' ')[0], version, 'la primera versión publicada es la actual');
  assert.ok(headings.slice(1).every((h) => !h.startsWith('Sin publicar')), '«Sin publicar» va arriba del todo');
});

test('PhishLens 2.3.0 en package.json, package-lock.json y el JSON exportado', () => {
  assert.equal(JSON.parse(read('package.json')).version, '2.3.0');
  const lock = JSON.parse(read('package-lock.json'));
  assert.equal(lock.version, '2.3.0');
  assert.equal(lock.packages[''].version, '2.3.0');
});
