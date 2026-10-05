import type { Bundle } from '../bundleIo.js';
import { DEFAULTS, id15, type LogType, type Wave } from '../model.js';
import { baselineDaysFor } from './actors.js';

export interface DayVolume {
  day: string;
  guestId15: string;
  /** AuraRequest rows with an ACTION_MESSAGE: the single primary measure. */
  controllerCalls: number;
  pageLoads: number;
  /** Guest rows in other event types for the same day. Corroboration only; never summed. */
  corroboration: Partial<Record<LogType, number>>;
}

export async function computeDayVolumes(b: Bundle): Promise<DayVolume[]> {
  const out = new Map<string, DayVolume>();
  const get = (day: string, guest: string) => {
    const k = `${guest}|${day}`;
    let v = out.get(k);
    if (!v) { v = { day, guestId15: guest, controllerCalls: 0, pageLoads: 0, corroboration: {} }; out.set(k, v); }
    return v;
  };
  const days = [...new Set(b.manifest.logs.map((l) => l.day))].sort();
  for (const day of days) {
    for await (const r of b.rows('AuraRequest', day)) {
      const g = id15(r.USER_ID) ?? id15(r.USER_ID_DERIVED);
      if (!g) continue;
      const v = get(day, g);
      if (r.ACTION_MESSAGE) v.controllerCalls++; else v.pageLoads++;
    }
  }
  for (const l of b.manifest.logs) {
    if (l.type === 'AuraRequest' || l.status !== 'collected') continue;
    for (const [g, n] of Object.entries(l.guestRowsByUser)) get(l.day, g).corroboration[l.type] = n;
  }
  return [...out.values()].sort((a, c) => a.day.localeCompare(c.day) || a.guestId15.localeCompare(c.guestId15));
}

export interface SpikeAssessment {
  day: string;
  /** null when AuraRequest was not collected for the day: unknown, never zero. */
  controllerCalls: number | null;
  baselineMedian: number | null;
  ratio: number | null;
  isSpike: boolean;
  /** Sum of TotalControllerEvents on that day: the detector's own sample, a different unit. */
  detectorSample: number | null;
}

function median(xs: number[]): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, c) => a - c);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

export function assessSpikes(b: Bundle, volumes: DayVolume[], wave: Wave, spikeRatio: number): SpikeAssessment[] {
  const own = volumes.filter((v) => v.guestId15 === wave.guestId15);
  const calls = (day: string) => own.find((v) => v.day === day)?.controllerCalls ?? 0;
  // Only days with AuraRequest traffic from this guest count as baseline: a day that exists only
  // through corroboration rows is not a baseline day, and no traffic at all means no baseline.
  const base = baselineDaysFor(b.manifest, wave.guestId15).filter((d) => own.some((v) => v.day === d && v.controllerCalls + v.pageLoads > 0));
  const baselineMedian = median(base.map(calls));
  const collected = (day: string) => b.manifest.logs.some((l) => l.type === 'AuraRequest' && l.day === day && l.status === 'collected');
  return wave.days.map((day) => {
    const c = collected(day) ? calls(day) : null;
    const ratio = baselineMedian && c !== null ? c / baselineMedian : null;
    // A zero median has no ratio; a quiet baseline must not hide a burst, so use the actor floor.
    const isSpike = c === null ? false : baselineMedian === 0 ? c >= DEFAULTS.outlierFloor : ratio !== null && ratio >= spikeRatio;
    const events = b.anomalies.filter((e) => wave.eventIds.includes(e.eventIdentifier) && e.eventDate.startsWith(day) && e.totalControllerEvents !== undefined);
    return {
      day,
      controllerCalls: c,
      baselineMedian,
      ratio,
      isSpike,
      detectorSample: events.length ? events.reduce((s, e) => s + (e.totalControllerEvents ?? 0), 0) : null,
    };
  });
}
