// Matriz de cobertura: cada regla que puede emitir un detector, con su técnica ATT&CK y dónde se prueba.
// Uso: npm run coverage (reescribe docs/coverage-matrix.md). tests/unit/coverage-matrix.test.js la compara.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LANGUAGE_PATTERNS } from '../src/data/lists.js';
import { techniquesFor } from '../src/data/mitre.js';
import { SAMPLES } from '../samples/index.js';
import { analyzeInput } from '../src/core/engine.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const PREFIX = '(?:auth|sender|headers|route|mime|links|lookalike|attachments|html|language|input)';
// Claves de notas del parser que src/detectors/mime.js traduce a otra regla.
const PARSER_NOTES = new Set(['mime.unterminated-multipart']);

const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');
const walk = (rel) => readdirSync(join(ROOT, rel), { withFileTypes: true }).flatMap((d) => {
  const path = `${rel}/${d.name}`;
  if (d.isDirectory()) return d.name === '__golden__' ? [] : walk(path);
  return d.name.endsWith('.js') ? [path] : [];
});

/** Todos los ids de regla que el código puede emitir, leídos del código fuente. */
export function ruleIds() {
  const ids = new Set();
  const sources = [...readdirSync(join(ROOT, 'src/detectors')).map((f) => `src/detectors/${f}`), 'src/core/engine.js'];
  for (const file of sources) {
    const src = read(file);
    for (const [, id] of src.matchAll(new RegExp(`['\`](${PREFIX}\\.[a-z0-9-]+)['\`]`, 'g'))) ids.add(id);
    // Ids con plantilla: auth.${check.key}, links.${id} y language.${category}.
    if (file.endsWith('/auth.js')) for (const [, key] of src.matchAll(/key: '([a-z]+)'/g)) ids.add(`auth.${key}`);
    if (file.endsWith('/links.js')) for (const [, key] of src.matchAll(/out\.push\(\['([a-z-]+)'/g)) ids.add(`links.${key}`);
  }
  for (const category of Object.keys(LANGUAGE_PATTERNS)) ids.add(`language.${category}`);
  return [...ids].filter((id) => !PARSER_NOTES.has(id)).sort();
}

export function buildMatrix() {
  const tests = walk('tests').map((path) => [path.replace(/^tests\//, ''), read(path)]);
  const fromSamples = new Map();
  for (const sample of SAMPLES) {
    for (const f of analyzeInput({ kind: 'eml', value: read(`samples/${sample.file}`) }).findings) {
      fromSamples.set(f.id, [...new Set([...(fromSamples.get(f.id) ?? []), sample.id.slice(0, 2)])]);
    }
  }
  return ruleIds().map((id) => {
    const inTests = tests.filter(([, text]) => text.includes(`'${id}'`) || text.includes(`"${id}"`) || text.includes(`${id}:`)).map(([p]) => p);
    const samples = fromSamples.get(id) ?? [];
    return {
      id,
      detector: id.split('.')[0],
      techniques: techniquesFor(id).map((t) => t.id),
      samples,
      tests: inTests,
      mark: inTests.length || samples.length ? '✅' : '⚠️',
    };
  });
}

export function renderMatrix(rows) {
  const uncovered = rows.filter((r) => r.mark !== '✅').length;
  const lines = rows.map((r) => `| \`${r.id}\` | ${r.techniques.join(', ') || '—'} | ${r.samples.join(', ') || '—'} | ${r.tests.length ? r.tests.map((t) => `\`${t}\``).join(', ') : '—'} | ${r.mark} |`);
  return `# Matriz de cobertura

Generada con \`npm run coverage\` (\`tools/gen-coverage.mjs\`); \`tests/unit/coverage-matrix.test.js\` falla si no está al día.
Una regla cuenta como probada si su id aparece en algún test o si alguna muestra de \`samples/\` la produce.

${rows.length} reglas, ${rows.length - uncovered} probadas${uncovered ? `, ${uncovered} sin probar (⚠️)` : ''}.

| Regla | ATT&CK | Muestras | Tests | |
| --- | --- | --- | --- | --- |
${lines.join('\n')}
`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  writeFileSync(join(ROOT, 'docs/coverage-matrix.md'), renderMatrix(buildMatrix()));
}
