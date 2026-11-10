// Estadísticas del panel (spec 3.0, §3): una sola pasada sobre el historial, con Map (nunca objetos
// indexados con texto del correo) y desempates por cadena, para que el orden de entrada no cambie nada.

const DAY = 24 * 60 * 60 * 1000;
const DAYS = 30;
const WEEKS = 26;
const LEVEL_KEYS = ['safe', 'suspicious', 'phishing', 'critical'];
const BAD = new Set(['phishing', 'critical']);
const RISKY = new Set(['suspicious', 'phishing', 'critical']);
const REPEAT_TYPES = ['domains', 'ips', 'hashes', 'sha1', 'md5'];
const ALL_TYPES = ['urls', 'domains', 'ips', 'emails', 'hashes', 'sha1', 'md5'];
const TOP = { techniques: 10, iocs: 20, senders: 10, domains: 10, campaigns: 5 };

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const dayOf = (ms) => new Date(ms).toISOString().slice(0, 10);
const startOfDay = (ms) => Math.floor(ms / DAY) * DAY;
/** Lunes (UTC) de la semana de `ms`. */
const startOfWeek = (ms) => {
  const d = startOfDay(ms);
  return d - ((new Date(d).getUTCDay() + 6) % 7) * DAY;
};
const zero = () => Object.fromEntries(LEVEL_KEYS.map((k) => [k, 0]));
const bump = (map, key, by = 1) => map.set(key, (map.get(key) ?? 0) + by);
const strings = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);

/** Los `n` primeros de un Map valor → veces, por veces descendente y luego por valor. */
function top(map, n, min = 1) {
  return [...map].filter(([, c]) => c >= min).sort((a, b) => b[1] - a[1] || cmp(a[0], b[0])).slice(0, n)
    .map(([value, count]) => ({ value, count }));
}

function timeline(points, nowMs) {
  const today = startOfDay(nowMs);
  const oldest = points.length ? Math.min(...points.map((p) => p.ms)) : today;
  if (today - startOfDay(oldest) < DAYS * DAY) {
    const buckets = Array.from({ length: DAYS }, (_, i) => ({ start: dayOf(today - (DAYS - 1 - i) * DAY), counts: zero() }));
    for (const p of points) buckets[DAYS - 1 - Math.round((today - startOfDay(p.ms)) / DAY)].counts[p.level] += 1;
    return { unit: 'day', buckets, omitted: 0 };
  }
  const thisWeek = startOfWeek(nowMs);
  const span = Math.round((thisWeek - startOfWeek(oldest)) / (7 * DAY)) + 1;
  const n = Math.min(span, WEEKS);
  const buckets = Array.from({ length: n }, (_, i) => ({ start: dayOf(thisWeek - (n - 1 - i) * 7 * DAY), counts: zero() }));
  let omitted = 0;
  for (const p of points) {
    const idx = n - 1 - Math.round((thisWeek - startOfWeek(p.ms)) / (7 * DAY));
    if (idx < 0) omitted++;
    else buckets[idx].counts[p.level] += 1;
  }
  return { unit: 'week', buckets, omitted };
}

/**
 * @param {Array<{savedAt: string, sha256: string, report: object}>} entries entradas válidas del historial
 * @param {{now?: Date, batches?: Array<{savedAt: string, campaigns: Array}>}} options
 */
export function historyStats(entries, { now = new Date(), batches = [] } = {}) {
  const nowMs = now.getTime();
  const points = [];
  const techniques = new Map();
  const techInfo = new Map();
  const iocCount = new Map();
  const distinct = new Set();
  const senders = new Map();
  const domains = new Map();
  const savedAtBySha = new Map();
  let bad = 0;
  let dangerous = 0;

  for (const e of entries) {
    const r = e.report ?? {};
    const level = LEVEL_KEYS.includes(r.level) ? r.level : 'safe';
    const parsed = Date.parse(e.savedAt);
    // Una fecha ilegible o futura cuenta hoy: el análisis existe aunque su fecha no cuadre.
    const ms = Number.isNaN(parsed) || parsed > nowMs ? nowMs : parsed;
    points.push({ ms, level });
    if (typeof e.sha256 === 'string') savedAtBySha.set(e.sha256, e.savedAt);
    if (BAD.has(level)) bad++;
    if ((r.findings ?? []).some((f) => f?.detector === 'attachments' && f.severity === 'high')) dangerous++;

    for (const t of new Map((r.techniques ?? []).filter((t) => typeof t?.id === 'string').map((t) => [t.id, t])).values()) {
      bump(techniques, t.id);
      const known = techInfo.get(t.id);
      if (!known || cmp(String(t.name), String(known.name)) < 0) techInfo.set(t.id, { name: String(t.name ?? t.id), tactic: String(t.tactic ?? '') });
    }
    for (const type of ALL_TYPES) {
      for (const v of new Set(strings(r.iocs?.[type]))) {
        distinct.add(`${type}|${v}`);
        if (REPEAT_TYPES.includes(type)) bump(iocCount, `${type}|${v}`);
      }
    }
    if (RISKY.has(level)) {
      const from = r.email?.from;
      if (typeof from?.address === 'string' && from.address) bump(senders, from.address.toLowerCase());
      if (typeof from?.domain === 'string' && from.domain) bump(domains, from.domain.toLowerCase());
    }
  }

  // Volver a analizar el mismo lote guarda otro registro: una campaña con el mismo nombre y los mismos
  // correos cuenta una vez, la más reciente.
  const byKey = new Map();
  for (const b of batches) {
    for (const c of Array.isArray(b?.campaigns) ? b.campaigns : []) {
      const emails = [...new Set(strings(c?.emails))].sort(cmp);
      const latestSha = emails.filter((s) => savedAtBySha.has(s))
        .sort((x, y) => cmp(savedAtBySha.get(y), savedAtBySha.get(x)) || cmp(x, y))[0] ?? null;
      const item = { name: String(c?.name ?? 'Campaña'), savedAt: String(b.savedAt ?? ''), emails: emails.length, reasons: strings(c?.reasons), latestSha };
      const key = JSON.stringify([item.name, emails]);
      const known = byKey.get(key);
      if (!known || cmp(item.savedAt, known.savedAt) > 0 || (item.savedAt === known.savedAt && cmp(item.reasons.join('|'), known.reasons.join('|')) < 0)) byKey.set(key, item);
    }
  }
  const campaigns = [...byKey.values()];
  campaigns.sort((a, b) => cmp(b.savedAt, a.savedAt) || cmp(a.name, b.name) || cmp(String(a.latestSha), String(b.latestSha)));

  const n = entries.length;
  return {
    totals: { analyses: n, phishingOrWorse: bad, campaigns: campaigns.length, distinctIocs: distinct.size, dangerousPct: n ? Math.round((100 * dangerous) / n) : 0 },
    timeline: timeline(points, nowMs),
    techniques: top(techniques, TOP.techniques).map(({ value, count }) => ({ id: value, ...techInfo.get(value), count })),
    iocs: [...iocCount].filter(([, c]) => c >= 2).map(([key, count]) => {
      const at = key.indexOf('|');
      return { type: key.slice(0, at), value: key.slice(at + 1), count };
    }).sort((a, b) => b.count - a.count || cmp(a.value, b.value) || cmp(a.type, b.type)).slice(0, TOP.iocs),
    senders: top(senders, TOP.senders),
    domains: top(domains, TOP.domains),
    campaigns: campaigns.slice(0, TOP.campaigns),
  };
}
