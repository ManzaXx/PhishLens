// Reglas en inglés (spec 3.1, PR15). Se ejecutan los tests de detectores, motor y muestras con un
// preload que guarda cada hallazgo creado (tests/helpers/capture-findings.mjs), y luego se comprueba,
// con los params reales que da cada detector, que el inglés no cae al español ni pierde parámetros.
import { test, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PLAIN } from '../../src/data/plain.js';
import { setLang } from '../../src/i18n/index.js';
import RULES_EN from '../../src/i18n/rules-en.js';
import { localizeReport, missingEnglish } from '../../src/ui/localize.js';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const UNIT = join(ROOT, 'tests/unit');
// Detectores ya traducidos. La Tarea 3 añade el resto.
export const DONE = new Set(['auth', 'sender', 'lookalike', 'headers', 'route']);

// Un proceso de test hijo con NODE_TEST_CONTEXT heredado no ejecuta nada: se quita.
const withoutTestContext = ({ NODE_TEST_CONTEXT, ...env }) => env;

let captured = [];
before(() => {
  const dir = mkdtempSync(join(tmpdir(), 'phishlens-findings-'));
  const files = readdirSync(UNIT).filter((f) => f.endsWith('.test.js') && f !== 'rules-en.test.js').map((f) => join(UNIT, f));
  const run = spawnSync(process.execPath, ['--import', join(ROOT, 'tests/helpers/capture-findings.mjs'), '--test', ...files], {
    cwd: ROOT, env: { ...withoutTestContext(process.env), CAPTURE_DIR: dir }, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  assert.equal(run.status, 0, run.stdout.slice(-2000));
  const rows = new Map();
  for (const name of readdirSync(dir)) for (const row of JSON.parse(readFileSync(join(dir, name), 'utf8'))) rows.set(JSON.stringify(row), row);
  rmSync(dir, { recursive: true, force: true });
  captured = [...rows.values()].filter((f) => Object.hasOwn(PLAIN, f.id));
});
afterEach(() => setLang('es'));

const detectorOf = (id) => id.split('.')[0];

test('cada regla traducida tiene título, detalle y texto llano en inglés con los params que da su detector', () => {
  setLang('en');
  const problems = [];
  for (const f of captured.filter((x) => DONE.has(detectorOf(x.id)))) {
    for (const m of missingEnglish({ findings: [f] })) problems.push(`${m} (${f.title})`);
    const [en] = localizeReport({ findings: [f] }).findings;
    if (en.title === f.title) problems.push(`${f.id}: título sin traducir (${f.title})`);
    if (en.detail === f.detail) problems.push(`${f.id}: detalle sin traducir (${f.detail.slice(0, 60)})`);
    if (en.plain.length > 140) problems.push(`${f.id}: texto llano de ${en.plain.length} caracteres`);
    if (/\{\w+\}/.test(en.title + en.detail + en.plain)) problems.push(`${f.id}: parámetro sin sustituir`);
  }
  assert.deepEqual([...new Set(problems)], []);
});

test('cada id traducido de PLAIN tiene sus tres claves en rules-en.js', () => {
  const has = (id, part) => Object.keys(RULES_EN).some((k) => k === `rule.${id}.${part}` || k.startsWith(`rule.${id}.${part}.`));
  const missing = Object.keys(PLAIN).filter((id) => DONE.has(detectorOf(id)))
    .flatMap((id) => ['title', 'detail', 'plain'].filter((p) => !has(id, p)).map((p) => `rule.${id}.${p}`));
  assert.deepEqual(missing, []);
});

test('el recorrido ve todas las reglas traducidas', () => {
  assert.ok(captured.length > 100, `solo ${captured.length} hallazgos`);
  const seen = new Set(captured.map((f) => f.id));
  assert.deepEqual(Object.keys(PLAIN).filter((id) => DONE.has(detectorOf(id)) && !seen.has(id)), []);
});
