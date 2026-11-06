// Tokens de diseño (spec 2.3, §4): contraste comprobado en los dos temas y ningún valor suelto fuera de tokens.css.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const read = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

/** Variables `--x: #hex;` del primer bloque que empieza por `selector {`. */
function block(css, selector) {
  const start = css.indexOf(`${selector} {`);
  assert.notEqual(start, -1, `falta el bloque ${selector}`);
  const body = css.slice(start, css.indexOf('}', start));
  return Object.fromEntries([...body.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})\s*;/gi)].map(([, k, v]) => [k, v.toLowerCase()]));
}

// Luminancia relativa y contraste de WCAG 2.x.
const channel = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const luminance = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => channel(parseInt(hex.slice(i, i + 2), 16) / 255));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

const PAIRS = [
  ['text', 'bg'], ['text', 'surface'], ['text-strong', 'surface'], ['muted', 'surface'], ['muted', 'surface-2'], ['muted', 'bg'],
  ['on-accent', 'accent'], ['accent-strong', 'accent-soft'], ['accent-strong', 'surface'],
  ...['safe', 'suspicious', 'phishing', 'critical', 'info', 'sev-high', 'sev-medium', 'sev-low'].map((k) => [k, `${k}-soft`]),
];

const css = existsSync(new URL('../../assets/css/tokens.css', import.meta.url)) ? read('assets/css/tokens.css') : '';
const THEMES = () => ({ claro: block(css, ':root'), oscuro: block(css, ':root[data-theme="dark"]') });

test('contraste ≥ 4.5 en claro y oscuro', () => {
  for (const [theme, vars] of Object.entries(THEMES())) {
    for (const [fg, bg] of PAIRS) {
      assert.ok(vars[fg] && vars[bg], `${theme}: falta --${fg} o --${bg}`);
      const ratio = contrast(vars[fg], vars[bg]);
      assert.ok(ratio >= 4.5, `${theme}: --${fg} sobre --${bg} da ${ratio.toFixed(2)}`);
    }
  }
});

test('los dos temas definen las mismas variables de color, y el oscuro del sistema es igual al elegido', () => {
  const { claro, oscuro } = THEMES();
  assert.deepEqual(Object.keys(oscuro).sort(), Object.keys(claro).sort());
  assert.deepEqual(block(css, '  :root:not([data-theme="light"])'), oscuro);
});

test('escalas de espacio, tipo y radio con los valores de la spec', () => {
  const root = css.slice(css.indexOf(':root {'), css.indexOf('}', css.indexOf(':root {')));
  const px = (name) => root.match(new RegExp(`--${name}:\\s*([0-9.]+)(px|rem)`))?.slice(1);
  const asPx = ([n, unit]) => (unit === 'rem' ? Number(n) * 16 : Number(n));
  assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((i) => asPx(px(`space-${i}`))), [4, 8, 12, 16, 20, 24, 32, 40, 48, 64]);
  assert.deepEqual(['xs', 'sm', 'md', 'lg', 'xl', '2xl', '3xl'].map((s) => asPx(px(`text-${s}`))), [12, 14, 16, 18, 22, 28, 36]);
  assert.deepEqual(['sm', 'md', 'lg', 'xl'].map((s) => asPx(px(`radius-${s}`))), [6, 10, 16, 24]);
});

test('ningún color ni tamaño suelto fuera de tokens.css', () => {
  const files = ['assets/css/styles.css', 'assets/css/components.css'].filter((p) => existsSync(new URL(`../../${p}`, import.meta.url)));
  for (const file of files) {
    const text = read(file).replace(/\/\*[\s\S]*?\*\//g, '');
    assert.doesNotMatch(text, /#[0-9a-f]{3,8}\b/i, `${file}: color en hexadecimal`);
    assert.doesNotMatch(text, /\b(rgb|rgba|hsl|hsla)\(/, `${file}: color rgb/hsl`);
    assert.doesNotMatch(text, /:root[^{]*\{[^}]*--/, `${file}: define tokens`);
    for (const [, value] of text.matchAll(/font-size:\s*([^;}]+)/g)) {
      assert.match(value.trim(), /^(var\(--text-[a-z0-9]+\)|inherit|[0-9.]+em|clamp\(var\(--text-[a-z0-9]+\),\s*[0-9.]+vw,\s*var\(--text-[a-z0-9]+\)\))$/, `${file}: font-size ${value}`);
    }
    for (const [, value] of text.matchAll(/(?<![-\w])font:\s*([^;}]+)/g)) {
      assert.doesNotMatch(value, /\d(px|rem)\b/, `${file}: font ${value}`);
    }
    for (const [, value] of text.matchAll(/border-radius:\s*([^;}]+)/g)) {
      assert.match(value.trim(), /^(var\(--radius-[a-z]+\)|50%|inherit)$/, `${file}: border-radius ${value}`);
    }
  }
});
