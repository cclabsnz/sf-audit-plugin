import type { Bundle } from '../bundleIo.js';
import type { BundleManifest, Wave } from '../model.js';
import { DEFAULTS, id15 } from '../model.js';
import type { IpRangeSet } from '../ipRanges.js';
import { parseActions } from './actions.js';

export interface Actor {
  id: string;
  block: string;
  ips: string[];
  days: string[];
  controllerCalls: number;
  pageLoads: number;
  firstSeen: string;
  lastSeen: string;
  hourly: Record<string, number>;
  steady: boolean;
  userAgents: Array<{ ua: string; count: number }>;
  emptyUaShare: number;
  markers: string[];
  hosting: string | null;
  hostingAssessed: boolean;
  sources: Array<'detector-ip' | 'outlier'>;
  /** Invocation counts per parsed action name (Controller.method). Bounded by distinct names. */
  actionCounts: Record<string, number>;
  /**
   * Actor IPs that many distinct users also log in from (a proxy or NAT). Logins from them are
   * not access, and one person's activity behind them cannot be separated in these logs.
   */
  sharedEgressIps: string[];
}

/**
 * IPs that more than DEFAULTS.sharedEgressUsers distinct users SUCCESSFULLY logged in from, counting
 * only users known not to have been created through a guest site. Failed logins (credential
 * stuffing) and self-registered throwaway accounts can therefore never make an attacker's IP look
 * like a proxy; an unknown creator does not count either.
 */
export function sharedEgressIps(b: Bundle): Set<string> {
  const guestIds = new Set(b.manifest.guests.map((g) => g.id15));
  const staff = new Set(b.followUp.users.filter((u) => u.createdById15 && !guestIds.has(u.createdById15)).map((u) => u.id15));
  const users = new Map<string, Set<string>>();
  for (const l of b.followUp.logins) {
    if (l.status !== 'Success' || !staff.has(l.userId15)) continue;
    const ip = normaliseIp(l.sourceIp);
    let s = users.get(ip);
    if (!s) { s = new Set(); users.set(ip, s); }
    s.add(l.userId15);
  }
  return new Set([...users.entries()].filter(([, s]) => s.size > DEFAULTS.sharedEgressUsers).map(([ip]) => ip));
}

const MARKERS: Array<{ name: string; re: RegExp }> = [
  { name: 'log4shell', re: /\$\{(?:jndi|::-|\$\{::-)/i },
  { name: 'path-traversal', re: /\.\.\/|%2e%2e%2f/i },
  { name: 'script-injection', re: /<script|%3cscript/i },
  { name: 'unicode-escape', re: /%u00/i },
];

/**
 * One canonical form per address, used on both sides of every IP comparison: trimmed,
 * lowercased, and for IPv6 fully expanded then compressed per RFC 5952 (leading zeros dropped,
 * the first longest run of two or more zero groups written as ::). Text that is not a plain
 * IPv6 address (including IPv4-embedded forms) is only trimmed and lowercased.
 */
export function normaliseIp(raw: string): string {
  const ip = (raw ?? '').trim().toLowerCase();
  if (!ip.includes(':') || ip.includes('.')) return ip;
  const halves = ip.split('::');
  if (halves.length > 2) return ip;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - left.length - right.length : 0;
  if ((halves.length === 1 && left.length !== 8) || fill < 0 || (halves.length === 2 && fill < 1)) return ip;
  const groups = [...left, ...Array<string>(fill).fill('0'), ...right];
  if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return ip;
  const hex = groups.map((g) => parseInt(g, 16).toString(16));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (hex[i] !== '0') { i++; continue; }
    let j = i;
    while (j < 8 && hex[j] === '0') j++;
    if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  if (bestLen < 2) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

export function blockOf(rawIp: string): string {
  const ip = rawIp.trim().toLowerCase();
  if (ip.includes(':')) {
    const [head, tail] = ip.split('::');
    const left = head ? head.split(':') : [];
    const right = tail !== undefined && tail !== '' ? tail.split(':') : [];
    const full = [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right];
    return `${full.slice(0, 4).join(':')}::/64`;
  }
  const p = ip.split('.');
  return p.length === 4 ? `${p[0]}.${p[1]}.${p[2]}.0/24` : ip;
}

/** Days collected for this guest that are not a wave day of any wave on that guest. */
export function baselineDaysFor(manifest: BundleManifest, guestId15: string): string[] {
  const waveDays = new Set(manifest.waves.filter((w) => w.guestId15 === guestId15).flatMap((w) => w.days));
  const days = new Set(manifest.logs.filter((l) => l.type === 'AuraRequest' && l.status === 'collected').map((l) => l.day));
  return [...days].filter((d) => !waveDays.has(d)).sort();
}

interface BlockAgg { ips: Set<string>; calls: number; loads: number; first: string; last: string; hourly: Map<string, number>; ua: Map<string, number>; markers: Set<string>; actions: Map<string, number> }

async function aggregate(b: Bundle, guestId15: string, day: string): Promise<Map<string, BlockAgg>> {
  const blocks = new Map<string, BlockAgg>();
  for await (const r of b.rows('AuraRequest', day)) {
    if (id15(r.USER_ID) !== guestId15 && id15(r.USER_ID_DERIVED) !== guestId15) continue;
    const ip = normaliseIp(r.CLIENT_IP ?? '');
    if (!ip) continue;
    const key = blockOf(ip);
    const ts = (r.TIMESTAMP_DERIVED ?? '').trim();
    let a = blocks.get(key);
    if (!a) { a = { ips: new Set(), calls: 0, loads: 0, first: ts, last: ts, hourly: new Map(), ua: new Map(), markers: new Set(), actions: new Map() }; blocks.set(key, a); }
    a.ips.add(ip);
    if (ts) {
      if (!a.first || ts < a.first) a.first = ts;
      if (ts > a.last) a.last = ts;
    }
    if (r.ACTION_MESSAGE) {
      a.calls++;
      const hour = ts.slice(0, 13);
      a.hourly.set(hour, (a.hourly.get(hour) ?? 0) + 1);
      for (const n of parseActions(r.ACTION_MESSAGE)) a.actions.set(n, (a.actions.get(n) ?? 0) + 1);
    } else a.loads++;
    const ua = r.USER_AGENT ?? '';
    a.ua.set(ua, (a.ua.get(ua) ?? 0) + 1);
    for (const m of MARKERS) if (m.re.test(ua) || m.re.test(r.URI ?? '')) a.markers.add(m.name);
  }
  return blocks;
}

function isSteady(hourly: Map<string, number>, first: string, last: string): boolean {
  const start = Date.parse(first.slice(0, 13) + ':00:00Z');
  const end = Date.parse(last.slice(0, 13) + ':00:00Z');
  const counts: number[] = [];
  for (let t = start; t <= end; t += 3_600_000) counts.push(hourly.get(new Date(t).toISOString().slice(0, 13)) ?? 0);
  if (counts.length < 3) return false;
  const mean = counts.reduce((s, c) => s + c, 0) / counts.length;
  const sd = Math.sqrt(counts.reduce((s, c) => s + (c - mean) ** 2, 0) / counts.length);
  return mean > 0 && sd / mean < 0.75;
}

/**
 * Actor blocks for a wave: any block whose controller calls on a wave day exceed
 * max(outlierFloor, outlierMultiple × the busiest block on any baseline day, ignoring blocks that
 * also appear on a wave day), plus any block
 * holding an anomaly event's SourceIp (which catches low-volume probes that are not spikes).
 */
export async function findActors(b: Bundle, wave: Wave, ranges: IpRangeSet | null): Promise<Actor[]> {
  const waveAggs = new Map<string, Map<string, BlockAgg>>();
  for (const day of wave.days) waveAggs.set(day, await aggregate(b, wave.guestId15, day));
  // Proxy vs attacker. A block is an outlier only when its wave-day calls exceed BOTH its own
  // history (3x its quietest baseline day, so an always-on proxy is never an actor) AND the
  // org's normal busiest block (3x the busiest block on the QUIETEST baseline day, which a scan
  // spilling past midnight into one baseline day cannot raise).
  const baselineDays = baselineDaysFor(b.manifest, wave.guestId15);
  const perDay: Array<Map<string, BlockAgg>> = [];
  for (const day of baselineDays) perDay.push(await aggregate(b, wave.guestId15, day));
  const waveBlocks = new Set([...waveAggs.values()].flatMap((m) => [...m.keys()]));
  // The org's normal busiest block ignores blocks also active on the wave days, so a scan that
  // spills past midnight cannot raise it; the quietest such day is the reference.
  const busiest = perDay.map((m) => [...m].reduce((max, [key, a]) => (waveBlocks.has(key) ? max : Math.max(max, a.calls)), 0));
  const globalRef = busiest.length ? busiest.reduce((a, c) => Math.min(a, c)) : 0;
  // A block's own history exempts it only when it is active across the day on EVERY baseline day
  // (12+ distinct hours): an always-on proxy qualifies, a spill clustered at midnight does not.
  const allDay = (key: string) => perDay.length > 0 && perDay.every((m) => (m.get(key)?.hourly.size ?? 0) >= 12);
  const ownMin = (key: string) => perDay.reduce((min, m) => Math.min(min, m.get(key)?.calls ?? 0), Infinity);
  const thresholdFor = (key: string) =>
    Math.max(DEFAULTS.outlierFloor, DEFAULTS.outlierMultiple * globalRef, allDay(key) ? DEFAULTS.outlierMultiple * ownMin(key) : 0);
  const shared = sharedEgressIps(b);
  const detectorBlocks = new Set(b.anomalies.filter((e) => wave.eventIds.includes(e.eventIdentifier) && e.sourceIp).map((e) => blockOf(normaliseIp(e.sourceIp!))));

  const merged = new Map<string, { agg: BlockAgg; days: Set<string>; sources: Set<'detector-ip' | 'outlier'> }>();
  for (const day of wave.days) {
    for (const [key, a] of waveAggs.get(day)!) {
      const sources: Array<'detector-ip' | 'outlier'> = [];
      if (a.calls > thresholdFor(key)) sources.push('outlier');
      if (detectorBlocks.has(key)) sources.push('detector-ip');
      if (sources.length === 0) continue;
      const m = merged.get(key);
      if (!m) { merged.set(key, { agg: a, days: new Set([day]), sources: new Set(sources) }); continue; }
      m.days.add(day);
      sources.forEach((s) => m.sources.add(s));
      a.ips.forEach((ip) => m.agg.ips.add(ip));
      m.agg.calls += a.calls; m.agg.loads += a.loads;
      if (a.first < m.agg.first) m.agg.first = a.first;
      if (a.last > m.agg.last) m.agg.last = a.last;
      a.hourly.forEach((v, k) => m.agg.hourly.set(k, (m.agg.hourly.get(k) ?? 0) + v));
      a.ua.forEach((v, k) => m.agg.ua.set(k, (m.agg.ua.get(k) ?? 0) + v));
      a.markers.forEach((x) => m.agg.markers.add(x));
      a.actions.forEach((v, k) => m.agg.actions.set(k, (m.agg.actions.get(k) ?? 0) + v));
    }
  }

  return [...merged.entries()]
    .sort((x, y) => y[1].agg.calls - x[1].agg.calls)
    .map(([block, { agg, days, sources }], i) => {
      const total = [...agg.ua.values()].reduce((s, c) => s + c, 0);
      const ips = [...agg.ips].sort();
      const v4 = !ips[0].includes(':');
      return {
        id: `${wave.id}-A${i + 1}`,
        block,
        ips,
        days: [...days].sort(),
        controllerCalls: agg.calls,
        pageLoads: agg.loads,
        firstSeen: agg.first,
        lastSeen: agg.last,
        hourly: Object.fromEntries([...agg.hourly.entries()].sort()),
        steady: isSteady(agg.hourly, agg.first, agg.last),
        userAgents: [...agg.ua.entries()].map(([ua, count]) => ({ ua, count })).sort((a, c) => c.count - a.count),
        emptyUaShare: total ? (agg.ua.get('') ?? 0) / total : 0,
        markers: [...agg.markers].sort(),
        hosting: ranges && v4 ? ranges.lookup(ips[0]) : null,
        hostingAssessed: ranges !== null && v4,
        sources: [...sources].sort() as Array<'detector-ip' | 'outlier'>,
        actionCounts: Object.fromEntries([...agg.actions.entries()].sort()),
        sharedEgressIps: ips.filter((ip) => shared.has(normaliseIp(ip))),
      };
    });
}
