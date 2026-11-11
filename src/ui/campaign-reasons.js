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
