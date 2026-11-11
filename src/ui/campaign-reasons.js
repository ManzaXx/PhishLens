// Pistas de una campaña en lenguaje llano; sin DOM, para el panel y para guardar el lote en el historial.
import { defang } from '../intel/ioc.js';
import { t } from '../i18n/index.js';

/** La pista en lenguaje llano, en el idioma activo. hashNames: sha256 -> nombre del adjunto. */
export function reasonText(r, hashNames) {
  if (r.type === 'sender-domain') return t('campaign.reason.sender-domain', { value: defang(r.value) });
  if (r.type === 'entry-ip') return t('campaign.reason.entry-ip', { value: defang(r.value) });
  if (r.type === 'link-domain') return t('campaign.reason.link-domain', { value: defang(r.value) });
  if (r.type === 'sha256') return t('campaign.reason.sha256', { name: hashNames.get(r.value) ?? t('campaign.reason.unnamed'), hash: r.value.slice(0, 12) });
  return t('campaign.reason.template', { percent: Math.round(Number(r.value) * 100) });
}

/** Nombre de la campaña en el idioma activo («Campaña 1» / «Campaign 1»); uno guardado sin referencia, tal cual. */
export const campaignName = (c) => (c?.nameRef?.code ? t(c.nameRef.code, c.nameRef.params) : c?.name);

/** sha256 -> nombre del adjunto, sacado de los nodos del grafo del lote. */
export const hashNames = (batch) => new Map((batch?.graph?.nodes ?? []).filter((n) => n.type === 'hash').map((n) => [n.value, n.label]));

const REASON_TYPES = new Set(['sender-domain', 'entry-ip', 'link-domain', 'sha256', 'template']);

/** Pista para guardar en el historial: tipo, valor y, si es un adjunto, su nombre. */
export const storedReason = (r, names) => ({ type: String(r.type), value: String(r.value), ...(r.type === 'sha256' ? { name: names.get(r.value) ?? null } : {}) });

/** Pistas de una campaña guardada en el idioma activo; un lote anterior a la 3.1 enseña su texto tal cual. */
export function campaignReasons(c) {
  const refs = Array.isArray(c?.reasonRefs) ? c.reasonRefs : [];
  const usable = refs.length && refs.length === (c.reasons ?? []).length
    && refs.every((r) => r && REASON_TYPES.has(r.type) && typeof r.value === 'string');
  if (!usable) return c?.reasons ?? [];
  return refs.map((r) => reasonText(r, new Map(typeof r.name === 'string' ? [[r.value, r.name]] : [])));
}
