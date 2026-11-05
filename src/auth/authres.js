// Parser de Authentication-Results (RFC 8601) en tiempo lineal y sin regex con retroceso.
// Solo lee lo que la cabecera DECLARA: si es de fiar lo decide auth/trust.js.

const MAX_LENGTH = 4096;
const MAX_RESULTS = 20;

/**
 * Quita comentarios "( … )" (anidados) y parte en tokens separados por espacios y ";",
 * respetando las comillas. Devuelve una lista de sentencias, cada una una lista de tokens.
 */
function tokenize(value) {
  const statements = [[]];
  let token = '';
  let depth = 0;
  let quoted = false;
  const flush = () => {
    if (token) statements.at(-1).push(token);
    token = '';
  };
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (quoted) {
      if (ch === '\\' && i + 1 < value.length) token += value[++i];
      else if (ch === '"') quoted = false;
      else token += ch;
    } else if (depth > 0) {
      if (ch === '(') depth++;
      else if (ch === ')') depth--;
    } else if (ch === '(') {
      depth = 1;
    } else if (ch === '"') {
      quoted = true;
    } else if (ch === ';') {
      flush();
      statements.push([]);
    } else if (/\s/.test(ch)) {
      flush();
    } else {
      token += ch;
    }
  }
  flush();
  return statements;
}

/** { authservId, results: [{ method, result, reason, props }] } */
export function parseAuthResults(value) {
  const statements = tokenize(String(value ?? '').slice(0, MAX_LENGTH));
  // Microsoft omite el authserv-id: si la primera palabra ya es "metodo=resultado", es un resultado.
  const anonymous = (statements[0]?.[0] ?? '').includes('=');
  const [head = [], ...rest] = anonymous ? [[], ...statements] : statements;
  const authservId = (head[0] ?? '').toLowerCase();
  const results = [];
  for (const tokens of rest) {
    if (results.length >= MAX_RESULTS) break;
    const first = tokens[0];
    if (!first || !first.includes('=')) continue;
    const eq = first.indexOf('=');
    const method = first.slice(0, eq).replace(/\/\d+$/, '').toLowerCase();
    const result = first.slice(eq + 1).toLowerCase();
    if (!method || !result) continue;
    let reason = '';
    const props = Object.create(null);
    for (const token of tokens.slice(1)) {
      const at = token.indexOf('=');
      if (at <= 0) continue;
      const key = token.slice(0, at).toLowerCase();
      const val = token.slice(at + 1);
      if (key === 'reason') reason = val;
      else if (key.includes('.')) props[key] = val;
    }
    results.push({ method, result, reason, props });
  }
  return { authservId, results };
}
