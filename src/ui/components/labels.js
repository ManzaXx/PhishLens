// Etiquetas compartidas por los componentes, en el idioma activo (spec 3.1). Set: claves raras
// ("constructor") no salen del prototipo.
import { t } from '../../i18n/index.js';

const SEVERITIES = new Set(['high', 'medium', 'low', 'info']);
const LEVELS = new Set(['high', 'medium', 'low']);

/** Gravedad conocida o 'info'. */
export const severityKey = (s) => (SEVERITIES.has(s) ? s : 'info');
/** «Grave», «Media», «Leve» o «Info». */
export const severityLabel = (s) => t(`common.severity.${severityKey(s)}`);
/** «fiabilidad alta»…; null si no es un nivel conocido. */
export const reliabilityLabel = (r) => (LEVELS.has(r) ? t(`common.reliability.${r}`) : null);
/** «alta», «media» o «baja»; null si no es un nivel conocido. */
export const confidenceLabel = (c) => (LEVELS.has(c) ? t(`common.confidence.${c}`) : null);

/** Texto de la insignia: el color nunca es la única señal del estado. */
export function authStateLabel(m) {
  switch (m.state) {
    case 'verified': return t('auth.state.verified');
    case 'declared-trusted': return t('auth.state.declared', { source: m.source || t('auth.state.receiver') });
    case 'declared-untrusted': return t('auth.state.untrusted');
    case 'unverifiable': return t('auth.state.unverifiable');
    default: return t('auth.state.none');
  }
}
