// Genera samples/data.js con el texto de cada muestra, para que la página no tenga que pedirlas por red
// (la CSP lleva connect-src 'none'). Uso: npm run samples. tests/unit/samples.test.js comprueba que está al día.
import { readFileSync, writeFileSync } from 'node:fs';
import { SAMPLES } from '../samples/index.js';

const dir = new URL('../samples/', import.meta.url);
const entries = SAMPLES.map((s) => `  ${JSON.stringify(s.id)}: ${JSON.stringify(readFileSync(new URL(s.file, dir), 'utf8'))},`);
writeFileSync(new URL('data.js', dir), `// Generado por tools/gen-samples.mjs a partir de los .eml de esta carpeta. No editar a mano.
export const SAMPLE_TEXTS = Object.freeze({
${entries.join('\n')}
});
`);
