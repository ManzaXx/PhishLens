// Detector del contenido HTML: formularios, scripts, URIs data:, texto oculto y emails que son solo una imagen.
import { finding } from '../core/finding.js';
import { scanHtml, htmlToText } from '../parser/html.js';

export const name = 'html';

const HIDDEN_STYLE = /(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\s*(?:;|$)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$))/i;
const EVENT_HANDLER = /\son[a-z]{3,20}\s*=/i;
const HIDDEN_THRESHOLD = 150;

export function detect(email) {
  const html = email.html ?? '';
  if (!html.trim()) return [];
  const flags = { form: null, script: null, dataUri: null };
  let images = 0;
  let hiddenDepth = 0;
  let hiddenTag = null;
  let hiddenChars = 0;

  // Recorrido lineal por etiquetas (las atributos de cada etiqueta son acotados).
  for (const token of scanHtml(html)) {
    if (token.text != null) {
      if (hiddenDepth > 0) hiddenChars += token.text.trim().length;
      continue;
    }
    const { tag, closing, raw } = token;
    if (closing) {
      if (hiddenDepth > 0 && tag === hiddenTag) hiddenDepth--;
      continue;
    }
    if (tag === 'form' || (tag === 'input' && /type\s*=\s*["']?password/i.test(raw))) flags.form ??= raw;
    if (tag === 'script' || tag === 'iframe' || tag === 'object' || tag === 'embed' || EVENT_HANDLER.test(raw)) flags.script ??= raw;
    if (/\s(?:href|src|action)\s*=\s*["']?\s*(?:data:(?!image\/)|javascript:|vbscript:)/i.test(raw)) flags.dataUri ??= raw;
    if (tag === 'img') images++;
    const style = /\sstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(raw);
    if (style && HIDDEN_STYLE.test(style[1] ?? style[2])) {
      if (hiddenDepth === 0) hiddenTag = tag;
      if (tag === hiddenTag) hiddenDepth++;
    }
  }
  // <script> lo consume el escáner: se busca aparte con un patrón lineal.
  if (!flags.script && /<script\b/i.test(html)) flags.script = '<script>';

  const out = [];
  const short = (s) => s.slice(0, 160);
  if (flags.form) {
    out.push(finding({
      id: 'html.form', detector: name, severity: 'high',
      title: 'Formulario dentro del email',
      params: {},
      detail: 'El email contiene un formulario para escribir datos. Ninguna empresa legítima te pide rellenar datos dentro de un correo.',
      evidence: short(flags.form),
    }));
  }
  if (flags.script) {
    out.push(finding({
      id: 'html.script', detector: name, severity: 'high',
      title: 'Código ejecutable en el email',
      params: {},
      detail: 'Contiene JavaScript, iframes u objetos incrustados. Los clientes de correo los bloquean, así que su presencia indica un mensaje malicioso.',
      evidence: short(flags.script),
    }));
  }
  if (flags.dataUri) {
    out.push(finding({
      id: 'html.data-uri', detector: name, severity: 'high',
      title: 'Enlace con código o contenido incrustado',
      params: {},
      detail: 'Un enlace data: o javascript: ejecuta código o abre una página creada dentro del propio email, sin dominio que se pueda comprobar.',
      evidence: short(flags.dataUri),
    }));
  }
  if (hiddenChars > HIDDEN_THRESHOLD) {
    out.push(finding({
      id: 'html.hidden-text', detector: name, severity: 'low',
      title: 'Mucho texto oculto',
      params: { chars: hiddenChars },
      detail: `Hay ${hiddenChars} caracteres invisibles para el lector. Se usa para engañar a los filtros antispam con texto inocente.`,
    }));
  }
  if (images > 0 && htmlToText(html).replace(/\s/g, '').length < 20 && !(email.text ?? '').trim()) {
    out.push(finding({
      id: 'html.image-only', detector: name, severity: 'low',
      title: 'Email formado solo por imágenes',
      params: {},
      detail: 'Sin texto que analizar, los filtros no pueden leer el mensaje. Es una técnica de evasión habitual.',
    }));
  }
  return out;
}
