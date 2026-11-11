// Preload solo para tests (tests/unit/rules-en.test.js): guarda en CAPTURE_DIR los hallazgos que crea
// cada proceso de test, para comprobar sus textos en inglés con los params reales de los detectores.
import { register } from 'node:module';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

register('./capture-hooks.mjs', import.meta.url);
globalThis.__capturedFindings = [];
process.on('exit', () => {
  const dir = process.env.CAPTURE_DIR;
  if (!dir) return;
  const seen = new Map();
  for (const f of globalThis.__capturedFindings) {
    const row = { id: f.id, detector: f.detector, title: f.title, detail: f.detail, plain: f.plain, brand: f.brand, params: f.params ?? null };
    seen.set(JSON.stringify(row), row);
  }
  writeFileSync(join(dir, `${process.pid}.json`), JSON.stringify([...seen.values()]));
});
