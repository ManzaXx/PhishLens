// Benchmark del motor: `npm run bench` reescribe docs/benchmark.md.
// Tiempo = mediana de 3 ejecuciones; memoria = heapUsed máximo observado durante ellas.
import { writeFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { analyzeInput } from '../src/core/engine.js';
import { buildEmail, SIZES } from '../tests/perf/build.js';

const RUNS = 3;
const mb = (n) => (n / 1024 / 1024).toFixed(1);
const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

const rows = [];
for (const [label, bytes] of SIZES) {
  const raw = buildEmail(bytes);
  const times = [];
  let heap = 0;
  for (let i = 0; i < RUNS; i++) {
    globalThis.gc?.();
    const start = performance.now();
    analyzeInput({ kind: 'eml', value: raw });
    times.push(performance.now() - start);
    heap = Math.max(heap, process.memoryUsage().heapUsed);
  }
  rows.push(`| ${label} | ${Math.round(median(times))} ms | ${mb(heap)} MB |`);
  console.log(rows.at(-1));
}

const md = `# Benchmark del motor

Generado con \`npm run bench\` (\`tools/bench.mjs\`). Cada correo lo crea \`tests/perf/build.js\`: HTML con 40 enlaces
y un adjunto PDF en base64 que rellena hasta el tamaño pedido. El tiempo es la mediana de ${RUNS} ejecuciones de
\`analyzeInput\`; la memoria es el \`heapUsed\` máximo medido justo después de cada una.

- Node: ${process.version}
- CPU: ${cpus()[0]?.model ?? 'desconocida'} (${cpus().length} núcleos)
- Fecha: ${new Date().toISOString().slice(0, 10)}

| Tamaño | Tiempo | Memoria (heapUsed) |
| --- | --- | --- |
${rows.join('\n')}

Un adjunto de más de 10 MB (\`LIMITS.attachmentBytes\`) no se decodifica entero: su tamaño real sale de la
longitud del base64. Por eso 25 MB no cuesta 2,5 veces lo que cuestan 10 MB.

El test \`tests/perf/perf.test.js\` exige menos de 4 s para 25 MB. En un navegador los números cambian según el
equipo, pero el orden de magnitud es el mismo porque el motor es el mismo código.
`;
writeFileSync(new URL('../docs/benchmark.md', import.meta.url), md);
