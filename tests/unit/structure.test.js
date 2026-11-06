// Comprueba la regla de dependencias de la arquitectura (docs/architecture.md)
// y que proyectoCiber/ se puede extraer como repositorio independiente.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const SRC = join(ROOT, 'src');

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? files(path) : path.endsWith('.js') ? [path] : [];
  });
}

const layerOf = (path) => relative(SRC, path).split(/[\\/]/)[0];
const importsOf = (path) => [...readFileSync(path, 'utf8').matchAll(/^\s*(?:import|export)\b[^'"]*from\s+['"]([^'"]+)['"]/gm)].map((m) => m[1]);
const targetLayer = (from, spec) => (spec.startsWith('.') ? layerOf(join(from, '..', spec)) : null);

const FORBIDDEN = {
  lib: ['core', 'parser', 'detectors', 'auth', 'intel', 'data', 'ui'],
  data: ['core', 'parser', 'detectors', 'auth', 'intel', 'ui'],
  parser: ['core', 'detectors', 'auth', 'intel', 'ui'],
  detectors: ['ui'],
  intel: ['ui'],
  core: ['ui'],
};

test('regla de dependencias entre capas', () => {
  const violations = [];
  for (const file of files(SRC)) {
    const layer = layerOf(file);
    for (const spec of importsOf(file)) {
      const target = targetLayer(file, spec);
      if (target && (FORBIDDEN[layer] ?? []).includes(target)) violations.push(`${relative(ROOT, file)} → ${spec}`);
    }
  }
  assert.deepEqual(violations, []);
});

test('solo src/ui/ toca el DOM', () => {
  const offenders = files(SRC)
    .filter((f) => layerOf(f) !== 'ui')
    .filter((f) => /\b(document|window)\./.test(readFileSync(f, 'utf8')));
  assert.deepEqual(offenders.map((f) => relative(ROOT, f)), []);
});

test('ningún import sale de proyectoCiber/', () => {
  const outside = [...files(SRC), ...files(join(ROOT, 'tests'))]
    .flatMap((f) => importsOf(f).filter((spec) => spec.startsWith('.') && relative(ROOT, join(f, '..', spec)).startsWith('..')).map((spec) => `${relative(ROOT, f)} → ${spec}`));
  assert.deepEqual(outside, []);
});

test('src/ui/components/ solo importa de ui/dom.js, de otros componentes y de data/', () => {
  const dir = join(SRC, 'ui', 'components');
  const allowed = (file, spec) => {
    const target = relative(SRC, join(file, '..', spec)).replaceAll('\\', '/');
    return target === 'ui/dom.js' || target.startsWith('ui/components/') || target.startsWith('data/');
  };
  const list = (() => { try { return files(dir); } catch { return []; } })();
  assert.ok(list.length > 0, 'no hay componentes');
  const violations = list.flatMap((f) => importsOf(f).filter((s) => !allowed(f, s)).map((s) => `${relative(ROOT, f)} → ${s}`));
  assert.deepEqual(violations, []);
});

test('src/parser/files/ solo importa de lib/, data/ y otros lectores de parser/files/', () => {
  const dir = join(SRC, 'parser', 'files');
  const allowed = (file, spec) => {
    const target = relative(SRC, join(file, '..', spec)).replaceAll('\\', '/');
    return target.startsWith('lib/') || target.startsWith('data/') || target.startsWith('parser/files/');
  };
  const violations = files(dir).flatMap((f) => importsOf(f).filter((s) => !allowed(f, s)).map((s) => `${relative(ROOT, f)} → ${s}`));
  assert.deepEqual(violations, []);
});
