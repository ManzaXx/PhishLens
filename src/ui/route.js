// Rutas del informe en la URL: '' es el modo sencillo y #analista/<vista> el modo analista.
// Funciones puras (sin DOM): la URL y el almacenamiento son entrada no fiable.

export const VIEWS = Object.freeze(['resumen', 'senales', 'vista-segura', 'autenticacion', 'cabeceras', 'adjuntos', 'urls', 'iocs', 'campanas', 'attack']);
export const VIEW_LABELS = Object.freeze({
  resumen: 'Resumen', senales: 'Señales', 'vista-segura': 'Vista segura', autenticacion: 'Autenticación',
  cabeceras: 'Cabeceras y ruta', adjuntos: 'Adjuntos', urls: 'URLs', iocs: 'IOCs', campanas: 'Campañas', attack: 'ATT&CK',
});
export const NAV_GROUPS = Object.freeze([
  Object.freeze({ label: 'Correo', views: Object.freeze(['resumen', 'senales', 'vista-segura', 'autenticacion', 'cabeceras', 'adjuntos']) }),
  Object.freeze({ label: 'Inteligencia', views: Object.freeze(['urls', 'iocs', 'campanas', 'attack']) }),
]);

const PREFIX = '#analista';
const SIMPLE = Object.freeze({ mode: 'simple', view: 'resumen' });
export const MODE_KEY = 'phishlens-mode';

/** ¿Es un hash del modo analista? (#analista o #analista/…, no #analistas). */
export const isAnalystHash = (hash) => typeof hash === 'string' && (hash === PREFIX || hash.startsWith(`${PREFIX}/`));

function decode(text) {
  try {
    return decodeURIComponent(text);
  } catch {
    return '';
  }
}

/** {mode, view} a partir de location.hash. Nunca lanza; lo desconocido cae en el resumen. */
export function parseRoute(hash) {
  if (!isAnalystHash(hash)) return { ...SIMPLE };
  const view = decode(hash.slice(PREFIX.length + 1));
  return { mode: 'analyst', view: VIEWS.includes(view) ? view : 'resumen' };
}

/** Hash de una ruta: '' en sencillo, #analista en el resumen y #analista/<vista> en el resto. */
export function formatRoute({ mode, view } = {}) {
  if (mode !== 'analyst') return '';
  return VIEWS.includes(view) && view !== 'resumen' ? `${PREFIX}/${view}` : PREFIX;
}

/** Modo al cargar: manda el hash; si no dice nada, el último elegido (si el almacenamiento deja leerlo). */
export function initialMode(storage, hash) {
  if (isAnalystHash(hash)) return 'analyst';
  try {
    return storage?.getItem(MODE_KEY) === 'analyst' ? 'analyst' : 'simple';
  } catch {
    return 'simple';
  }
}

/** ¿Tiene esta vista algo que enseñar en este informe? context.batch: el lote analizado, si lo hay. */
export function hasView(view, report, context = {}) {
  if (!VIEWS.includes(view)) return false;
  if (view === 'campanas') return (context?.batch?.entries?.length ?? 0) >= 2;
  if (view === 'autenticacion' || view === 'cabeceras') {
    return Boolean(report?.email?.from || report?.email?.authResults);
  }
  if (view === 'urls') return (report?.email?.links?.length ?? 0) > 0;
  if (view === 'adjuntos') return (report?.email?.attachments?.length ?? 0) > 0;
  return true;
}

/** La vista pedida, o el resumen si no tiene contenido en este informe (p. ej. tras analizar una URL). */
export const resolveView = (view, report, context = {}) => (hasView(view, report, context) ? view : 'resumen');
