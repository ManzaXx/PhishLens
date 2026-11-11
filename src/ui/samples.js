// Títulos de las muestras y lotes de ejemplo en el idioma activo (samples/index.js trae los dos).
import { getLang } from '../i18n/index.js';

export const sampleTitle = (s) => (getLang() === 'en' && s.titleEn ? s.titleEn : s.title);
export const batchTitle = sampleTitle;
