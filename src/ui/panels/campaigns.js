// Panel «Campañas»: correos del lote que comparten infraestructura, un adjunto o la misma plantilla.
import { el, nextId } from '../dom.js';
import { reasonText, hashNames } from '../campaign-reasons.js';
import { LEVELS } from '../../core/scoring.js';
import { emptyState } from '../components/empty-state.js';
import { t, getLang, LOCALE } from '../../i18n/index.js';

const LEVEL_LABEL = new Map(LEVELS.map((l) => [l.level, l.label]));
const emailsCount = (n) => t('campaigns.emails.count', { count: n });

/** Campaña elegida (por id) o la primera. */
export const pickCampaign = (campaigns, id) => campaigns.find((c) => c.id === id) ?? campaigns[0] ?? null;

export function campaignsPanel(report, { batch, campaign } = {}) {
  const campaigns = batch?.campaigns ?? [];
  if (!campaigns.length) return emptyState(t('campaigns.empty.title'), t('campaigns.empty.text'));
  const chosen = pickCampaign(campaigns, campaign);
  const names = new Map(batch.entries.map((e) => [e.key, e]));
  const fileNames = hashNames(batch);

  const list = el('ul', { className: 'campaign-list', attrs: { 'aria-label': t('campaigns.list') } });
  for (const c of campaigns) {
    const attrs = { type: 'button', 'data-action': 'pick-campaign', 'data-id': c.id };
    if (c === chosen) attrs['aria-current'] = 'true';
    list.append(el('li', {}, el('button', {
      className: `campaign-list__btn level-${c.level}`,
      text: `${c.name} · ${emailsCount(c.emails.length)} · ${LEVEL_LABEL.get(c.level) ?? ''}`,
      attrs,
    })));
  }

  const emails = el('ul', { className: 'campaign__emails' });
  const byName = (a, b) => String(names.get(a)?.name ?? a).localeCompare(String(names.get(b)?.name ?? b), LOCALE[getLang()]);
  for (const key of [...chosen.emails].sort(byName)) {
    const e = names.get(key);
    emails.append(el('li', {}, el('button', {
      className: 'btn btn--small campaign__email',
      text: `${e?.name ?? key} · ${e?.report.email?.subject || t('campaigns.noSubject')}`,
      attrs: { type: 'button', 'data-action': 'pick-email', 'data-key': key },
    })));
  }
  const reasons = el('ul', { className: 'campaign__reasons' });
  for (const r of chosen.reasons) {
    const who = [...r.emails].sort(byName).map((k) => names.get(k)?.name ?? k).join(', ');
    reasons.append(el('li', {}, el('span', { className: 'campaign__reason', text: reasonText(r, fileNames) }), el('span', { className: 'campaign__who', text: who })));
  }
  const techniques = el('ul', { className: 'campaign__techniques' });
  for (const t of chosen.techniques) techniques.append(el('li', { text: `${t.id} · ${t.name}` }));

  const id = nextId('campaign');
  const block = (title, body) => el('section', { className: 'campaign__block' }, el('h4', { className: 'group__title', text: title }), body);
  const detail = el('section', { className: 'campaign card', attrs: { 'aria-labelledby': id } },
    el('h3', { className: 'campaign__title', text: `${chosen.name}: ${emailsCount(chosen.emails.length)}`, attrs: { id, tabindex: '-1' } }),
    block(t('campaigns.emails'), emails),
    block(t('campaigns.reasons'), reasons),
    block(t('campaigns.brand'), el('p', { text: chosen.brands.length ? chosen.brands.join(', ') : t('campaigns.noBrand') })),
    block(t('campaigns.techniques'), chosen.techniques.length ? techniques : el('p', { text: t('campaigns.noTechniques') })));
  return el('div', { className: 'campaigns' },
    el('p', { className: 'hint', text: t('campaigns.hint') }),
    list, detail);
}
