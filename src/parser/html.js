// Tratamiento de HTML sin DOM: escáner lineal, texto visible y enlaces <a href>.
import { own } from '../lib/text.js';

const ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  aacute: 'á', eacute: 'é', iacute: 'í', oacute: 'ó', uacute: 'ú', ntilde: 'ñ',
  Aacute: 'Á', Eacute: 'É', Iacute: 'Í', Oacute: 'Ó', Uacute: 'Ú', Ntilde: 'Ñ',
  uuml: 'ü', iexcl: '¡', iquest: '¿', euro: '€', copy: '©', reg: '®',
};

export function decodeEntities(text) {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const code = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try {
        return String.fromCodePoint(code);
      } catch {
        return m;
      }
    }
    return own(ENTITIES, e) ?? m;
  });
}

const RAW_TEXT_TAGS = new Set(['script', 'style', 'head']);
const BLOCK_END = /^(br|p|div|tr|li|h\d)$/;

/**
 * Recorre el HTML en tiempo lineal y emite trozos de texto y etiquetas.
 * Se evita usar regex con retroceso sobre todo el documento: un email malicioso
 * con miles de "<" sin cerrar podría bloquear la pestaña.
 */
export function* scanHtml(html) {
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf('<', i);
    if (lt < 0) {
      yield { text: html.slice(i) };
      return;
    }
    if (lt > i) yield { text: html.slice(i, lt) };
    if (html.startsWith('<!--', lt)) {
      const end = html.indexOf('-->', lt + 4);
      if (end < 0) return;
      i = end + 3;
      continue;
    }
    const gt = html.indexOf('>', lt + 1);
    if (gt < 0) {
      yield { text: html.slice(lt) };
      return;
    }
    const raw = html.slice(lt, gt + 1);
    const m = /^<(\/?)([a-z][a-z0-9]*)/i.exec(raw);
    i = gt + 1;
    if (!m) {
      yield { text: raw };
      continue;
    }
    const tag = m[2].toLowerCase();
    const closing = m[1] === '/';
    if (!closing && RAW_TEXT_TAGS.has(tag)) {
      const close = new RegExp(`</${tag}`, 'ig');
      close.lastIndex = i;
      const found = close.exec(html);
      if (!found) return;
      const endGt = html.indexOf('>', found.index);
      i = endGt < 0 ? html.length : endGt + 1;
      continue;
    }
    yield { tag, closing, raw };
  }
}

function normalizeText(text) {
  return decodeEntities(text)
    .replace(/\u00a0/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** Convierte HTML en texto legible sin usar el DOM. */
export function htmlToText(html) {
  const out = [];
  for (const token of scanHtml(String(html))) {
    if (token.text != null) out.push(token.text);
    else out.push((token.closing || token.tag === 'br') && BLOCK_END.test(token.tag) ? '\n' : ' ');
  }
  return normalizeText(out.join(''));
}

/** Extrae los enlaces <a href> del HTML con su texto visible. */
export function extractAnchors(html) {
  const links = [];
  let current = null;
  const finish = () => {
    if (current) links.push({ text: normalizeText(current.parts.join('')), href: current.href });
    current = null;
  };
  for (const token of scanHtml(html)) {
    if (token.text != null) {
      current?.parts.push(token.text);
    } else if (token.tag === 'a') {
      finish();
      if (token.closing) continue;
      const m = /\shref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(token.raw);
      const href = decodeEntities((m?.[1] ?? m?.[2] ?? m?.[3] ?? '').trim());
      if (href && !/^(mailto|tel|#)/i.test(href)) current = { href, parts: [] };
    } else if (current) {
      current.parts.push(' ');
    }
  }
  finish();
  return links;
}
