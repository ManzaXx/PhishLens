// El analizador de la app (src/ui/analysis-worker.js) en una página limpia con la CSP de index.html: analiza un
// texto en el worker y comprueba que el informe es el mismo que en el hilo principal. Resultado en window.__app.
import { createAnalyzer } from '../../../src/ui/analysis-worker.js';
import { analyzeInput } from '../../../src/core/engine.js';

const input = { kind: 'text', value: 'Verifica tu cuenta urgentemente: http://203.0.113.9/login', rules: [] };
const out = { step: 'inicio' };
window.__appPartial = out;
try {
  const a = createAnalyzer();
  out.available = a.available;
  out.step = 'run';
  const report = await a.run(input);
  out.mode = a.mode;
  out.lastError = a.lastError;
  out.step = 'cancel';
  out.score = report.score;
  out.sameAsMain = JSON.stringify(report) === JSON.stringify(analyzeInput(input));
  // Cancelar un análisis en curso y volver a analizar después.
  const p = a.run({ kind: 'text', value: 'x'.repeat(200000) });
  out.cancelled = a.cancel();
  out.cancelError = await p.then(() => 'resuelto', (e) => e.name);
  out.afterCancel = (await a.run(input)).score;
  out.modeAfterCancel = a.mode;
  out.step = 'fin';
} catch (e) {
  out.error = String(e?.message ?? e);
}
document.getElementById('out').textContent = JSON.stringify(out, null, 2);
window.__app = out;
