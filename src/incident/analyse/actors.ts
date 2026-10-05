import type { Bundle } from '../bundleIo.js';
import type { BundleManifest, Wave } from '../model.js';
import { DEFAULTS, id15 } from '../model.js';
import type { IpRangeSet } from '../ipRanges.js';

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
  /** Controller-bearing ACTION_MESSAGE values, kept for action and response analysis. */
  actionMessages: string[];
}

const MARKERS: Array<{ name: string; re: RegExp }> = [
  { name: 'log4shell', re: /\$\{(?:jndi|::-|\$\{::-)/i },
  { name: 'path-traversal', re: /\.\.\/|%2e%2e%2f/i },
  { name: 'script-injection', re: /<script|%3cscript/i },
  { name: 'unicode-escape', re: /%u00/i },
];

export function blockOf(ip: string): string {
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

interface BlockAgg { ips: Set<string>; calls: number; loads: number; first: string; last: string; hourly: Map<string, number>; ua: Map<string, number>; markers: Set<string>; messages: string[] }

async function aggregate(b: Bundle, guestId15: string, day: string, keepMessages: boolean): Promise<Map<string, BlockAgg>> {
  const blocks = new Map<string, BlockAgg>();
  for await (const r of b.rows('AuraRequest', day)) {
    if (id15(r.USER_ID) !== guestId15 && id15(r.USER_ID_DERIVED) !== guestId15) continue;
    const ip = (r.CLIENT_IP ?? '').trim();
    if (!ip) continue;
    const key = blockOf(ip);
    let a = blocks.get(key);
    if (!a) { a = { ips: new Set(), calls: 0, loads: 0, first: r.TIMESTAMP_DERIVED, last: r.TIMESTAMP_DERIVED, hourly: new Map(), ua: new Map(), markers: new Set(), messages: [] }; blocks.set(key, a); }
    a.ips.add(ip);
    const ts = r.TIMESTAMP_DERIVED ?? '';
    if (ts < a.first) a.first = ts;
    if (ts > a.last) a.last = ts;
    if (r.ACTION_MESSAGE) {
      a.calls++;
      const hour = ts.slice(0, 13);
      a.hourly.set(hour, (a.hourly.get(hour) ?? 0) + 1);
      if (keepMessages) a.messages.push(r.ACTION_MESSAGE);
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
 * max(outlierFloor, outlierMultiple × the busiest block on any baseline day), plus any block
 * holding an anomaly event's SourceIp (which catches low-volume probes that are not spikes).
 */
export async function findActors(b: Bundle, wave: Wave, ranges: IpRangeSet | null): Promise<Actor[]> {
  let baselineMax = 0;
  for (const day of baselineDaysFor(b.manifest, wave.guestId15)) {
    for (const a of (await aggregate(b, wave.guestId15, day, false)).values()) baselineMax = Math.max(baselineMax, a.calls);
  }
  const threshold = Math.max(DEFAULTS.outlierFloor, DEFAULTS.outlierMultiple * baselineMax);
  const detectorBlocks = new Set(b.anomalies.filter((e) => wave.eventIds.includes(e.eventIdentifier) && e.sourceIp).map((e) => blockOf(e.sourceIp!)));

  const merged = new Map<string, { agg: BlockAgg; days: Set<string>; sources: Set<'detector-ip' | 'outlier'> }>();
  for (const day of wave.days) {
    for (const [key, a] of await aggregate(b, wave.guestId15, day, true)) {
      const sources: Array<'detector-ip' | 'outlier'> = [];
      if (a.calls > threshold) sources.push('outlier');
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
      m.agg.messages.push(...a.messages);
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
        actionMessages: agg.messages,
      };
    });
}
