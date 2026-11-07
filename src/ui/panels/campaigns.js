// Panel «Campañas»: correos del lote que comparten infraestructura, un adjunto o la misma plantilla.
import { el, nextId } from '../dom.js';
import { defang } from '../../intel/ioc.js';
import { LEVELS } from '../../core/scoring.js';
import { emptyState } from '../components/empty-state.js';

const LEVEL_LABEL = new Map(LEVELS.map((l) => [l.level, l.label]));
const count = (n, one, many) => `${n} ${n === 1 ? one : many}`;

/** La pista en lenguaje llano. hashNames: sha256 -> nombre del adjunto. */
function reasonText(r, hashNames) {
  if (r.type === 'sender-domain') return `Mismo dominio de envío: ${defang(r.value)}`;
  if (r.type === 'entry-ip') return `Misma IP de entrada: ${defang(r.value)}`;
  if (r.type === 'link-domain') return `Mismo dominio en los enlaces: ${defang(r.value)}`;
  if (r.type === 'sha256') return `Mismo adjunto: ${hashNames.get(r.value) ?? 'sin nombre'} (SHA-256 ${r.value.slice(0, 12)}…)`;
  return `Misma plantilla: ${Math.round(Number(r.value) * 100)} % parecida`;
}

/** Campaña elegida (por id) o la primera. */
export const pickCampaign = (campaigns, id) => campaigns.find((c) => c.id === id) ?? campaigns[0] ?? null;

export function campaignsPanel(report, { batch, campaign } = {}) {
  const campaigns = batch?.campaigns ?? [];
  if (!campaigns.length) return emptyState('Sin campañas', 'Ningún correo del lote comparte infraestructura, adjuntos ni plantilla.');
  const chosen = pickCampaign(campaigns, campaign);
  const names = new Map(batch.entries.map((e) => [e.key, e]));
  const hashNames = new Map((batch.graph?.nodes ?? []).filter((n) => n.type === 'hash').map((n) => [n.value, n.label]));

  const list = el('ul', { className: 'campaign-list', attrs: { 'aria-label': 'Campañas del lote' } });
  for (const c of campaigns) {
    const attrs = { type: 'button', 'data-action': 'pick-campaign', 'data-id': c.id };
    if (c === chosen) attrs['aria-current'] = 'true';
    list.append(el('li', {}, el('button', {
      className: `campaign-list__btn level-${c.level}`,
      text: `${c.name} · ${count(c.emails.length, 'correo', 'correos')} · ${LEVEL_LABEL.get(c.level) ?? ''}`,
      attrs,
    })));
  }

  const emails = el('ul', { className: 'campaign__emails' });
  const byName = (a, b) => String(names.get(a)?.name ?? a).localeCompare(String(names.get(b)?.name ?? b), 'es');
  for (const key of [...chosen.emails].sort(byName)) {
    const e = names.get(key);
    emails.append(el('li', {}, el('button', {
      className: 'btn btn--small campaign__email',
      text: `${e?.name ?? key} · ${e?.report.email?.subject || 'Sin asunto'}`,
      attrs: { type: 'button', 'data-action': 'pick-email', 'data-key': key },
    })));
  }
  const reasons = el('ul', { className: 'campaign__reasons' });
  for (const r of chosen.reasons) {
    const who = [...r.emails].sort(byName).map((k) => names.get(k)?.name ?? k).join(', ');
    reasons.append(el('li', {}, el('span', { className: 'campaign__reason', text: reasonText(r, hashNames) }), el('span', { className: 'campaign__who', text: who })));
  }
  const techniques = el('ul', { className: 'campaign__techniques' });
  for (const t of chosen.techniques) techniques.append(el('li', { text: `${t.id} · ${t.name}` }));

  const id = nextId('campaign');
  const block = (title, body) => el('section', { className: 'campaign__block' }, el('h4', { className: 'group__title', text: title }), body);
  const detail = el('section', { className: 'campaign card', attrs: { 'aria-labelledby': id } },
    el('h3', { className: 'campaign__title', text: `${chosen.name}: ${count(chosen.emails.length, 'correo', 'correos')}`, attrs: { id, tabindex: '-1' } }),
    block('Correos', emails),
    block('Qué tienen en común', reasons),
    block('Marca que suplanta', el('p', { text: chosen.brands.length ? chosen.brands.join(', ') : 'No se ha identificado ninguna marca.' })),
    block('Técnicas ATT&CK', chosen.techniques.length ? techniques : el('p', { text: 'Ninguna.' })));
  return el('div', { className: 'campaigns' },
    el('p', { className: 'hint', text: 'Correos que comparten remitente, IP de entrada, dominio de enlace, adjunto o plantilla. Es una pista, no una prueba: revisa lo que tienen en común.' }),
    list, detail);
}
