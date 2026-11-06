// HTML smuggling (T1027.006): un HTML adjunto que fabrica el fichero dentro del navegador
// a partir de datos codificados, para que no pase por los filtros del correo.
const SCAN_BYTES = 2 * 1024 * 1024;
const utf8 = new TextDecoder('utf-8');

const MARKERS = [
  ['new Blob(', (s) => /new\s{0,10}blob\s{0,10}\(/.test(s)],
  ['URL.createObjectURL', (s) => s.includes('url.createobjecturl')],
  ['msSaveOrOpenBlob', (s) => s.includes('mssaveoropenblob')],
  ['atob + download', (s) => s.includes('atob(') && /\bdownload\s{0,10}=/.test(s)],
];

/** `{suspicious, markers}`: hace falta un <script> y al menos una señal. */
export function htmlSmuggling(bytes) {
  const text = utf8.decode(bytes.subarray(0, SCAN_BYTES)).toLowerCase();
  if (!text.includes('<script')) return { suspicious: false, markers: [] };
  const markers = MARKERS.filter(([, test]) => test(text)).map(([label]) => label);
  return { suspicious: markers.length > 0, markers };
}
