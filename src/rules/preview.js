// Vista previa de las reglas propias sobre el historial (spec 3.0, §5.2). El historial no guarda el
// correo, así que solo se pueden probar las reglas cuyas condiciones miran únicamente finding.id.
import { evaluate } from './evaluate.js';

function onlyFindings(node) {
  if (Array.isArray(node?.all)) return node.all.every(onlyFindings);
  if (Array.isArray(node?.any)) return node.any.every(onlyFindings);
  if (node?.not) return onlyFindings(node.not);
  return node?.field === 'finding.id';
}

const findingsOf = (entry) => {
  const list = entry?.report?.findings;
  return Array.isArray(list) ? list.filter((f) => f && typeof f.id === 'string') : [];
};

/** Por regla: si se puede probar con lo guardado y en cuántos de los análisis guardados se cumpliría. */
export function previewRules(rules, entries) {
  const list = Array.isArray(entries) ? entries : [];
  return rules.map((rule) => {
    const testable = onlyFindings(rule.when);
    const matches = testable ? list.filter((e) => evaluate(rule, null, findingsOf(e)).match).length : 0;
    return { id: rule.id, title: rule.title, testable, matches, total: list.length };
  });
}
