// Etiquetas compartidas por los componentes. Map: claves raras ("constructor") no salen del prototipo.
export const SEVERITY = new Map([['high', 'Grave'], ['medium', 'Media'], ['low', 'Leve'], ['info', 'Info']]);
export const RELIABILITY = new Map([['high', 'fiabilidad alta'], ['medium', 'fiabilidad media'], ['low', 'fiabilidad baja']]);
export const CONFIDENCE = new Map([['high', 'alta'], ['medium', 'media'], ['low', 'baja']]);

/** Gravedad conocida o 'info'. */
export const severityKey = (s) => (SEVERITY.has(s) ? s : 'info');
