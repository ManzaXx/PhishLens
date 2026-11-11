// Hook de carga solo para tests: envuelve finding() para guardar cada hallazgo que se crea.
export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  if (!url.endsWith('/src/core/finding.js')) return result;
  const source = String(result.source).replace('export function finding(', 'function originalFinding(');
  return {
    ...result,
    source: `${source}\nexport function finding(spec) {
  const f = originalFinding(spec);
  // Solo cuentan los hallazgos que crea src/ (detectores y motor), no los que fabrica un test a mano.
  const caller = (new Error().stack ?? '').split('\\n')[2] ?? '';
  if (/\\/src\\/(detectors|core)\\//.test(caller)) globalThis.__capturedFindings?.push(f);
  return f;
}\n`,
  };
}
