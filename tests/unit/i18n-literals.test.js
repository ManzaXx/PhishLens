// Sin texto fijo en la interfaz (spec 3.1): todo lo que se ve pasa por t(). Busca literales con letras
// en las posiciones donde un texto acaba en pantalla o en un lector de pantalla.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const files = (dir) => readdirSync(dir).flatMap((n) => {
  const p = join(dir, n);
  return statSync(p).isDirectory() ? files(p) : p.endsWith('.js') ? [p] : [];
});

// Literal entre comillas simples o plantilla, con dos letras seguidas fuera de ${…}.
const STR = String.raw`(?:'(?:[^'\\\n]|\\.)*'|\x60(?:[^\x60\\]|\\.)*\x60)`;
const SPOTS = [
  String.raw`\btext:\s*`, String.raw`\.textContent\s*=\s*`, String.raw`'aria-label':\s*`, String.raw`\btitle:\s*`,
  String.raw`\bplaceholder:\s*`, String.raw`\blabel:\s*`, String.raw`\bcaption:\s*`, String.raw`\bannounce\(\s*`,
  String.raw`\bbutton\(\s*`, String.raw`\bsetAttribute\('(?:aria-label|title)',\s*`,
];
const RE = new RegExp(`(?:${SPOTS.join('|')})(${STR})`, 'g');
const hasWords = (lit) => /\p{L}{2,}/u.test(lit.slice(1, -1).replace(/\$\{[^}]*\}/g, ''));

export function literals(code) {
  const out = [];
  code.split('\n').forEach((line, i) => {
    // Comentarios, y las líneas marcadas «i18n: ignore» (ejemplos técnicos que no cambian de idioma).
    if (/^\s*(\/\/|\*|\/\*)/.test(line) || line.includes('// i18n: ignore')) return;
    for (const m of line.matchAll(RE)) if (hasWords(m[1])) out.push(`${i + 1}: ${m[1].slice(0, 60)}`);
  });
  return out;
}

test('el detector encuentra literales y deja pasar t() e interpolaciones', () => {
  assert.equal(literals("el('p', { text: 'Hola mundo' })").length, 1);
  assert.equal(literals("el('p', { text: t('a.b') })").length, 0);
  assert.equal(literals('el(\'p\', { text: `${a} · ${b}` })').length, 0);
  assert.equal(literals("announce(`Lote de ${n} correos`)").length, 1);
  assert.equal(literals("node.textContent = '—';").length, 0);
  assert.equal(literals("el('p', { text: 'v=spf1 -all' }), // i18n: ignore (ejemplo)").length, 0);
});

test('src/ui/ no tiene textos fijos fuera de t()', () => {
  const found = files(join(ROOT, 'src', 'ui')).flatMap((f) => literals(readFileSync(f, 'utf8')).map((l) => `${relative(ROOT, f)}:${l}`));
  assert.deepEqual(found, []);
});
