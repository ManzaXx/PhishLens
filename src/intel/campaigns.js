// Campañas: correos del lote que comparten infraestructura, un adjunto o el mismo kit (spec 2.3, §5.2).
// Determinista e independiente del orden. Solo participan correos que no son "probablemente legítimos".
import { registrableDomain } from '../parser/url.js';
import { sha256 } from '../lib/sha256.js';
import { FREE_MAIL_DOMAINS, URL_SHORTENERS, TRACKING_DOMAINS, SHARED_MAIL_INFRA, SOCIAL_DOMAINS, HOSTING_PLATFORMS } from '../data/lists.js';
import { BRANDS } from '../data/brands.js';
import { LEVELS } from '../core/scoring.js';
import { entryIp, senderDomain, linkUrls } from './graph.js';
import { kitOf, similarity, KIT_THRESHOLD } from './kit.js';

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const reg = (set) => new Set([...set].map((d) => registrableDomain(d)));
// Dominios que comparten correos sin relación entre sí: no son pista de campaña.
const COMMON_LINKS = new Set([...reg(URL_SHORTENERS), ...reg(TRACKING_DOMAINS), ...reg(SOCIAL_DOMAINS), ...BRANDS.flatMap((b) => b.domains.map(registrableDomain))]);
const HOSTING = reg(HOSTING_PLATFORMS);
const COMMON_SENDERS = reg(FREE_MAIL_DOMAINS);
const SEVERITY = LEVELS.map((l) => l.level); // de más a menos grave

/** La IP de entrada es de un gran proveedor (correo gratuito, Gmail, Outlook, SES…) y la comparten millones. */
export function sharedEntry(report, sender) {
  if (sender && COMMON_SENDERS.has(registrableDomain(sender))) return true;
  const hop = (report?.email?.route ?? []).find((h) => h.entry);
  return [hop?.rdns, hop?.helo].some((name) => {
    const host = String(name ?? '').toLowerCase().replace(/\.$/, '');
    return host && [...SHARED_MAIL_INFRA].some((d) => host === d || host.endsWith(`.${d}`));
  });
}

/** Pistas de infraestructura y adjuntos de un correo: [kind, type, value]. */
function cluesOf(report) {
  const out = [];
  const sender = senderDomain(report);
  if (sender && !COMMON_SENDERS.has(registrableDomain(sender))) out.push(['infra', 'sender-domain', sender]);
  const ip = entryIp(report);
  if (ip && !sharedEntry(report, sender)) out.push(['infra', 'entry-ip', ip]);
  for (const url of linkUrls(report)) {
    if (url.isIp) continue;
    const host = url.hostname.toLowerCase().replace(/^www\./, '');
    const d = registrableDomain(host);
    if (COMMON_LINKS.has(d)) continue;
    // En una plataforma de alojamiento cada cliente es un subdominio: la pista es el host, no la plataforma.
    if (HOSTING.has(d) || [...HOSTING_PLATFORMS].some((p) => host.endsWith(`.${p}`))) {
      if (!HOSTING_PLATFORMS.has(host) && host !== d) out.push(['infra', 'link-domain', host]);
    } else out.push(['infra', 'link-domain', d]);
  }
  for (const a of report?.email?.attachments ?? []) if (a.sha256) out.push(['hash', 'sha256', a.sha256]);
  return out;
}

/**
 * @param {Array<{key, name, report}>} entries
 * @returns {Array<{id, name, emails, reasons, brands, techniques, level}>}
 */
export function findCampaigns(entries) {
  const list = entries.filter((e) => e.report?.level && e.report.level !== 'safe').sort((a, b) => cmp(a.key, b.key));
  const parent = new Map(list.map((e) => [e.key, e.key]));
  const find = (k) => {
    while (parent.get(k) !== k) {
      parent.set(k, parent.get(parent.get(k)));
      k = parent.get(k);
    }
    return k;
  };
  const union = (a, b) => {
    const [ra, rb] = [find(a), find(b)];
    if (ra !== rb) parent.set(ra > rb ? ra : rb, ra > rb ? rb : ra);
  };

  // Pista -> correos que la tienen.
  const clues = new Map();
  for (const e of list) {
    for (const [kind, type, value] of cluesOf(e.report)) {
      const id = `${kind}\u0000${type}\u0000${value}`;
      if (!clues.has(id)) clues.set(id, { kind, type, value, emails: new Set() });
      clues.get(id).emails.add(e.key);
    }
  }
  for (const c of clues.values()) {
    const [first, ...rest] = [...c.emails];
    for (const k of rest) union(first, k);
  }
  const kits = list.map((e) => kitOf(e.report));
  const kitPairs = [];
  for (let i = 0; i < list.length; i++) {
    for (let j = i + 1; j < list.length; j++) {
      const s = similarity(kits[i], kits[j]);
      if (s >= KIT_THRESHOLD) {
        union(list[i].key, list[j].key);
        kitPairs.push({ kind: 'kit', type: 'template', value: s.toFixed(2), emails: [list[i].key, list[j].key] });
      }
    }
  }

  const groups = new Map();
  for (const e of list) {
    const root = find(e.key);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(e);
  }
  const campaigns = [...groups.values()].filter((g) => g.length >= 2).map((group) => {
    const keys = group.map((e) => e.key);
    const inside = new Set(keys);
    const reasons = [
      ...[...clues.values()]
        .map((c) => ({ kind: c.kind, type: c.type, value: c.value, emails: [...c.emails].filter((k) => inside.has(k)).sort(cmp) }))
        .filter((c) => c.emails.length >= 2),
      ...kitPairs.filter((p) => inside.has(p.emails[0])),
    ].sort((a, b) => cmp(a.kind, b.kind) || cmp(a.type, b.type) || cmp(a.value, b.value) || cmp(a.emails.join(), b.emails.join()));
    const brands = [...new Set(group.flatMap((e) => (e.report.findings ?? []).map((f) => f.brand).filter((b) => typeof b === 'string' && b)))].sort(cmp);
    const techniques = [...new Map(group.flatMap((e) => e.report.techniques ?? []).map((t) => [t.id, t])).values()].sort((a, b) => cmp(a.id, b.id));
    const level = SEVERITY.find((l) => group.some((e) => e.report.level === l));
    return { id: `campaign:${sha256(keys.join(',')).slice(0, 16)}`, emails: keys, reasons, brands, techniques, level };
  });
  return campaigns
    .sort((a, b) => b.emails.length - a.emails.length || cmp(a.emails[0], b.emails[0]))
    .map((c, i) => ({ id: c.id, name: `Campaña ${i + 1}`, ...c }));
}
