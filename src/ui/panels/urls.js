// Panel «URLs» (spec 2.3, §5.3): cada enlace desenvuelto sin visitarlo, con su cadena de saltos y lo que
// tiene de raro. Todo va defanged y en textContent: nada de esta vista se puede pulsar.
import { el, decimal } from '../dom.js';
import { defang } from '../../intel/ioc.js';
import { analyzeUrl, shortHop } from '../../intel/url.js';
import { emptyState } from '../components/empty-state.js';

const LIMIT = 100;

const VIA = {
  google: 'Google lo envolvía', safelinks: 'Safe Links de Outlook lo envolvía', facebook: 'Facebook lo envolvía',
  linkedin: 'LinkedIn lo envolvía', base64: 'escondido en base64',
};
const viaText = (via) => (via.startsWith('param:') ? `sacado del parámetro «${via.slice(6)}»` : VIA[via] ?? via);

// Peso de cada rasgo para ordenar: primero lo más grave.
const WEIGHT = { obfuscatedIp: 3, credentials: 3, nestedRedirect: 2, openRedirect: 2, highEntropy: 1, nonStandardPort: 1 };
const score = (a) => Object.entries(a.flags).reduce((n, [k, v]) => n + (v ? WEIGHT[k] : 0), 0);

function reasons(a) {
  const out = [];
  const jumps = a.hops.length - 1;
  if (a.flags.obfuscatedIp) out.push('La dirección IP está escrita de forma rara para que no se reconozca.');
  if (a.flags.credentials) out.push('Lleva un usuario y una contraseña antes del dominio.');
  if (a.flags.nestedRedirect) out.push(`Salta ${jumps} veces antes de llegar al destino.`);
  if (a.flags.openRedirect) out.push(`Empieza en ${defang(new URL(a.hops[0].href).hostname)} y esa web reenvía a otro dominio.`);
  if (a.flags.highEntropy) out.push('El nombre del dominio parece escrito al azar.');
  if (a.flags.nonStandardPort) out.push(`Usa el puerto ${a.port}, que las webs normales no indican.`);
  if (a.cycle) out.push('La cadena vuelve sobre sí misma: se ha cortado ahí.');
  if (a.truncated) out.push('Tiene más de 10 saltos: solo se muestran los 10 primeros.');
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
      el('span', { className: 'url-card__via', text: ` · ${i === 0 ? 'enlace del correo' : viaText(h.via)}` }))));
  return el('article', { className: `url-card${why.length ? ' url-card--flagged' : ''}` },
    el('h3', { className: 'url-card__host', text: host }),
    el('dl', { className: 'url-card__facts' },
      el('dt', { text: 'Destino final' }), el('dd', { className: 'url-card__url', text: defang(a.final) }),
      el('dt', { text: 'Aleatoriedad' }), el('dd', { text: `dominio ${decimal(a.entropy.host.toFixed(1))} · ruta ${decimal(a.entropy.path.toFixed(1))} bits por carácter` })),
    a.hops.length > 1 ? el('div', {}, el('p', { className: 'url-card__label', text: `Cadena (${last} ${last === 1 ? 'salto' : 'saltos'})` }), hops) : null,
    el('p', { className: 'url-card__label', text: 'Por qué es sospechosa' }),
    why.length
      ? el('ul', { className: 'url-card__reasons' }, ...why.map((t) => el('li', { text: t })))
      : el('p', { className: 'url-card__clean', text: 'Nada raro en la dirección en sí. Revisa también las señales del correo.' }),
    shared >= 2 ? el('p', { className: 'url-card__shared', text: `Aparece en ${shared} correos del lote.` }) : null);
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
  if (!all.length) return emptyState('Sin enlaces', 'Este correo no tiene enlaces que revisar.');
  all.sort((x, y) => score(y) - score(x) || (x.final < y.final ? -1 : x.final > y.final ? 1 : 0));
  const counts = options.batch ? hostCounts(options.batch) : new Map();
  return el('div', { className: 'stack' },
    el('p', { className: 'hint', text: 'Cada enlace desenvuelto sin visitarlo: de dónde sale, a dónde lleva y qué tiene de raro. Nada de esta vista se puede pulsar.' }),
    all.length > LIMIT ? el('p', { className: 'graph__note', text: `Se muestran ${LIMIT} de ${all.length} enlaces, primero los más sospechosos.` }) : null,
    el('div', { className: 'url-cards' }, ...all.slice(0, LIMIT).map((a) => card(a, counts.get(a.hostname) ?? 0))));
}
