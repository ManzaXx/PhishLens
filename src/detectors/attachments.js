// Detector de adjuntos peligrosos. Mira el nombre y, desde la 2.3, lo que el parser ha
// leído por dentro (`attachment.inspection`): tipo real, lista de un ZIP, macros, PDF activo.
// Nunca abre, descomprime ni ejecuta nada.
import { finding } from '../core/finding.js';
import { DANGEROUS_EXTENSIONS, MACRO_EXTENSIONS, ARCHIVE_EXTENSIONS } from '../data/lists.js';

export const name = 'attachments';

const DOCUMENT_LIKE = /^(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|csv|rtf|odt)$/;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/;
const DISK_IMAGE = new Set(['iso', 'img', 'vhd', 'vhdx']);
// Tipos reales que ejecutan algo al abrirlos: si se disfrazan de documento, es grave.
const EXECUTES = new Set(['pe', 'elf', 'lnk', 'script', 'html']);

// Extensiones legítimas para cada tipo real: un .docx ES un ZIP y no por eso es un disfraz.
const COMPATIBLE = new Map(Object.entries({
  pe: 'exe dll scr com cpl ocx sys drv efi mui ax pif',
  elf: 'so elf bin run out ko axf',
  zip: 'zip docx xlsx pptx docm xlsm pptm dotx dotm xltx xltm xlam ppsx ppsm potx potm ppam vsdx odt ods odp odg epub jar apk kmz xpi appx msix nupkg whl ipa',
  ole: 'doc dot xls xlt xla ppt pot pps msg msi msp mpp pub vsd',
  pdf: 'pdf ai',
  rtf: 'rtf doc wri',
  iso: 'iso img udf',
  lnk: 'lnk',
  html: 'htm html shtml xhtml hta',
  script: 'sh bash zsh ksh py pl rb php command cgi run',
}).map(([type, list]) => [type, new Set(list.split(' '))]));

// Windows quita los puntos y espacios del final: «factura.exe.» se abre como un .exe.
const windowsName = (n) => String(n).replace(/[.\s]+$/, '');

const extOf = (n) => {
  const parts = windowsName(n).toLowerCase().split('.').map((p) => p.trim());
  return parts.length > 1 ? parts.at(-1) : null;
};

function byName(filename, add, skip) {
  if (BIDI.test(filename)) {
    add('attachments.rtl-override', 'high', 'Nombre de adjunto invertido',
      'El nombre contiene un carácter que invierte el sentido del texto: "factura\u202Efdp.exe" se ve como "facturaexe.pdf".',
      filename.replace(/[\u202A-\u202E\u2066-\u2069]/g, '⟦RLO⟧'));
    return;
  }
  const parts = windowsName(filename).toLowerCase().split('.').map((p) => p.trim());
  if (parts.length < 2) return;
  const ext = parts.at(-1);
  const prev = parts.length > 2 ? parts.at(-2) : null;
  if (DANGEROUS_EXTENSIONS.has(ext) && prev && DOCUMENT_LIKE.test(prev)) {
    add('attachments.double-extension', 'high', 'Adjunto con doble extensión',
      `"${filename}" parece un .${prev} pero en realidad es un .${ext}. Es un truco clásico para colar malware.`, filename);
  } else if (DISK_IMAGE.has(ext) || ext === 'lnk') {
    // Tienen su propia regla, más concreta, más abajo.
  } else if (DANGEROUS_EXTENSIONS.has(ext)) {
    add('attachments.dangerous', 'high', 'Adjunto que puede ejecutar código',
      `Los ficheros .${ext} pueden ejecutar programas en tu ordenador al abrirlos.`, filename);
  } else if (MACRO_EXTENSIONS.has(ext)) {
    if (!skip.has('macro')) {
      add('attachments.macro', 'medium', 'Documento con macros', `Los .${ext} pueden contener macros, una vía habitual de infección.`, filename);
    }
  } else if (ARCHIVE_EXTENSIONS.has(ext)) {
    add('attachments.archive', 'low', 'Fichero comprimido',
      'Los comprimidos se usan para esconder ejecutables de los filtros antivirus del correo.', filename);
  }
}

function pdfSeverity(tokens) {
  const has = (t) => tokens.includes(t);
  if (has('Launch') || (has('EmbeddedFile') && has('JavaScript'))) return 'high';
  if (has('JavaScript') || has('EmbeddedFile')) return 'medium';
  if (has('OpenAction') || has('AA')) return 'low';
  return null;
}

function byContent(filename, insp, add) {
  const ext = extOf(filename);
  const real = insp?.partial ? null : insp?.realType;
  if (real && real !== 'unknown' && !COMPATIBLE.get(real)?.has(ext)) {
    const severity = EXECUTES.has(real) && (!ext || DOCUMENT_LIKE.test(ext)) ? 'high' : 'medium';
    add('attachments.type-mismatch', severity, 'El adjunto no es lo que dice ser',
      `"${filename}" dice ser ${ext ? `un .${ext}` : 'un archivo sin extensión'}, pero por dentro es: ${insp.realLabel}.`, filename);
  }
  const zip = insp?.zip;
  if (zip?.ok) {
    const inner = zip.entries.find((e) => DANGEROUS_EXTENSIONS.has(extOf(e.name)));
    if (inner) {
      add('attachments.archive-executable', 'high', 'Comprimido con un programa dentro',
        `"${filename}" lleva dentro "${inner.name}", que puede ejecutar código al abrirlo.`, inner.name);
    }
    const locked = zip.entries.filter((e) => e.encrypted);
    if (locked.length) {
      add('attachments.encrypted-archive', 'medium', 'Comprimido con contraseña',
        `${locked.length} de ${zip.entries.length} entradas de "${filename}" están cifradas: ni el filtro del correo ni PhishLens pueden ver qué son.`, filename);
    }
  }
  const pdfLevel = insp?.pdf && pdfSeverity(insp.pdf.tokens);
  if (pdfLevel) {
    add('attachments.pdf-active', pdfLevel, 'PDF que actúa al abrirlo',
      `"${filename}" contiene ${insp.pdf.tokens.map((t) => `/${t}`).join(', ')}: instrucciones para que el visor haga algo por su cuenta.`, filename);
  }
  if (insp?.ole?.hasVba || zip?.vbaProject) {
    add('attachments.ole-macro', 'high', 'Documento con macros de verdad',
      `"${filename}" lleva un proyecto de macros VBA dentro, no solo una extensión que lo permite.`, filename);
  }
  if (insp?.html?.suspicious) {
    add('attachments.html-smuggling', 'high', 'HTML que fabrica un archivo',
      `"${filename}" tiene un script con ${insp.html.markers.join(', ')}: así se crea un archivo en tu equipo sin que pase por el filtro del correo.`, filename);
  }
  if (DISK_IMAGE.has(ext) || real === 'iso') {
    add('attachments.disk-image', 'high', 'Imagen de disco adjunta',
      `"${filename}" es una imagen de disco. Lo que sale de ella no lleva la marca de «descargado de Internet» y Windows no avisa al abrirlo.`, filename);
  }
  if (ext === 'lnk' || real === 'lnk') {
    add('attachments.lnk', 'high', 'Acceso directo de Windows',
      `"${filename}" es un acceso directo: puede lanzar cualquier orden con un doble clic.`, filename);
  }
}

export function detect(email) {
  const out = [];
  for (const { filename, inspection } of email.attachments ?? []) {
    const add = (id, severity, title, detail, evidence) => out.push(finding({ id, detector: name, severity, title, detail, evidence }));
    const insp = inspection ?? null;
    const hasVba = !insp?.partial && (insp?.ole?.hasVba || insp?.zip?.vbaProject);
    byName(filename, add, new Set(hasVba ? ['macro'] : []));
    byContent(filename, insp?.partial ? { ...insp, zip: null, ole: null, pdf: null, html: null } : insp, add);
  }
  return out;
}
