// Panel «URLs» (spec 2.3, §5.3): cada enlace desenvuelto sin visitarlo, con su cadena de saltos y lo que
// tiene de raro. Todo va defanged y en textContent: nada de esta vista se puede pulsar.
import { el, decimal } from '../dom.js';
import { defang } from '../../intel/ioc.js';
import { analyzeUrl, shortHop } from '../../intel/url.js';
import { emptyState } from '../components/empty-state.js';
import { t } from '../../i18n/index.js';

const LIMIT = 100;

const VIA = new Set(['google', 'safelinks', 'facebook', 'linkedin', 'base64']);
const viaText = (via) => (via.startsWith('param:') ? t('urls.via.param', { name: via.slice(6) }) : VIA.has(via) ? t(`urls.via.${via}`) : via);

// Peso de cada rasgo para ordenar: primero lo más grave.
const WEIGHT = { obfuscatedIp: 3, credentials: 3, nestedRedirect: 2, openRedirect: 2, highEntropy: 1, nonStandardPort: 1 };
const score = (a) => Object.entries(a.flags).reduce((n, [k, v]) => n + (v ? WEIGHT[k] : 0), 0);

function reasons(a) {
  const out = [];
  const jumps = a.hops.length - 1;
  if (a.flags.obfuscatedIp) out.push(t('urls.why.obfuscatedIp'));
  if (a.flags.credentials) out.push(t('urls.why.credentials'));
  if (a.flags.nestedRedirect) out.push(t('urls.why.nested', { n: jumps }));
  if (a.flags.openRedirect) out.push(t('urls.why.open', { host: defang(new URL(a.hops[0].href).hostname) }));
  if (a.flags.highEntropy) out.push(t('urls.why.entropy'));
  if (a.flags.nonStandardPort) out.push(t('urls.why.port', { port: a.port }));
  if (a.cycle) out.push(t('urls.why.cycle'));
  if (a.truncated) out.push(t('urls.why.truncated'));
  return out;
}

/** Destinos finales (host) de cada correo del lote, para decir cuántos lo comparten. */
function hostCounts(batch) {
  const counts = new Map();
  for (const entry of batch?.entries ?? []) {
    const hosts = new Set((entry.report?.email?.links ?? []).map((l) => analyzeUrl(l.href)?.hostname).filter(Boolean));
    for (const h of hosts) counts.set(h, (counts.get(h) ?? 0) + 1);
  }
  return counts;
}

function card(a, shared) {
  const host = a.unicodeHost !== a.hostname ? `${defang(a.hostname)} (${defang(a.unicodeHost)})` : defang(a.hostname);
  const why = reasons(a);
  // Los saltos intermedios van acortados (sin el base64 ni la query entera); el destino, completo.
  const last = a.hops.length - 1;
  const hops = el('ol', { className: 'url-card__hops' },
    ...a.hops.map((h, i) => el('li', {},
      el('span', { className: 'url-card__url', text: defang(i < last ? shortHop(h.href, a.hops[i + 1].via) : h.href) }),
      el('span', { className: 'url-card__via', text: ` · ${i === 0 ? t('urls.via.email') : viaText(h.via)}` }))));
  return el('article', { className: `url-card${why.length ? ' url-card--flagged' : ''}` },
    el('h3', { className: 'url-card__host', text: host }),
    el('dl', { className: 'url-card__facts' },
      el('dt', { text: t('urls.final') }), el('dd', { className: 'url-card__url', text: defang(a.final) }),
      el('dt', { text: t('urls.entropy') }), el('dd', { text: t('urls.entropy.value', { host: decimal(a.entropy.host.toFixed(1)), path: decimal(a.entropy.path.toFixed(1)) }) })),
    a.hops.length > 1 ? el('div', {}, el('p', { className: 'url-card__label', text: t('urls.chain', { count: last }) }), hops) : null,
    el('p', { className: 'url-card__label', text: t('urls.why') }),
    why.length
      ? el('ul', { className: 'url-card__reasons' }, ...why.map((line) => el('li', { text: line })))
      : el('p', { className: 'url-card__clean', text: t('urls.clean') }),
    shared >= 2 ? el('p', { className: 'url-card__shared', text: t('urls.shared', { n: shared }) }) : null);
}

export function urlsPanel(report, options = {}) {
  const seen = new Set();
  const all = [];
  for (const link of report?.email?.links ?? []) {
    if (seen.has(link.href)) continue;
    seen.add(link.href);
    const a = analyzeUrl(link.href);
    if (a) all.push(a);
  }
  if (!all.length) return emptyState(t('urls.empty.title'), t('urls.empty.text'));
  all.sort((x, y) => score(y) - score(x) || (x.final < y.final ? -1 : x.final > y.final ? 1 : 0));
  const counts = options.batch ? hostCounts(options.batch) : new Map();
  return el('div', { className: 'stack' },
    el('p', { className: 'hint', text: t('urls.hint') }),
    all.length > LIMIT ? el('p', { className: 'graph__note', text: t('urls.limit', { shown: LIMIT, total: all.length }) }) : null,
    el('div', { className: 'url-cards' }, ...all.slice(0, LIMIT).map((a) => card(a, counts.get(a.hostname) ?? 0))));
}
