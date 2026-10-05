// src/incident/collect/discoverWaves.ts
import type { SoqlClient } from '@cclabsnz/sf-core';
import { degrades } from './orgErrors.js';
import { id15, type AnomalyEvent, type GuestUser, type Wave } from '../model.js';

interface StoreRow {
  EventIdentifier: string; EventDate: string; Score?: number; Summary?: string; Username?: string; UserId?: string;
  SourceIp?: string | null; UserAgent?: string | null; TotalControllerEvents?: number | null; RequestedEntities?: string | null; SoqlCommands?: string | null;
}

/** GuestUserAnomalyEventStore rejects ORDER BY EventDate ASC, so sorting happens client-side. */
export async function readAnomalies(soql: SoqlClient, sinceDays: number): Promise<{ available: boolean; events: AnomalyEvent[] }> {
  const days = Math.max(1, Math.min(365, Math.floor(sinceDays)));
  try {
    const rows = await soql.queryAll<StoreRow>(
      'SELECT EventIdentifier, EventDate, Score, Summary, Username, UserId, SourceIp, UserAgent, TotalControllerEvents, RequestedEntities, SoqlCommands ' +
      `FROM GuestUserAnomalyEventStore WHERE EventDate = LAST_N_DAYS:${days}`);
    const events = rows.map((r) => ({
      eventIdentifier: r.EventIdentifier,
      eventDate: r.EventDate,
      score: Number(r.Score ?? 0),
      userId15: id15(r.UserId) ?? '',
      username: r.Username ?? '',
      sourceIp: r.SourceIp ?? undefined,
      userAgent: r.UserAgent ?? undefined,
      summary: r.Summary ?? undefined,
      totalControllerEvents: r.TotalControllerEvents ?? undefined,
      requestedEntities: r.RequestedEntities ?? undefined,
      soqlCommands: r.SoqlCommands ?? undefined,
    })).sort((a, c) => a.eventDate.localeCompare(c.eventDate));
    return { available: true, events };
  } catch (e) {
    if (!degrades(e)) throw e;
    return { available: false, events: [] };
  }
}

const dayOf = (iso: string) => new Date(iso).toISOString().slice(0, 10);
const nextDay = (d: string) => new Date(Date.parse(`${d}T00:00:00Z`) + 86_400_000).toISOString().slice(0, 10);
const siteFor = (g: GuestUser | undefined, fallback: string) => g?.siteNames[0] ?? g?.username ?? fallback;

export function buildWaves(events: AnomalyEvent[], guests: GuestUser[], opts: { event?: string }): Wave[] {
  const byGuest = new Map<string, AnomalyEvent[]>();
  for (const e of [...events].sort((a, c) => a.eventDate.localeCompare(c.eventDate))) {
    const list = byGuest.get(e.userId15) ?? [];
    list.push(e);
    byGuest.set(e.userId15, list);
  }
  const raw: Array<Omit<Wave, 'id'>> = [];
  for (const [guestId15, list] of byGuest) {
    const g = guests.find((x) => x.id15 === guestId15);
    let cur: Omit<Wave, 'id'> | undefined;
    for (const e of list) {
      const d = dayOf(e.eventDate);
      const last = cur?.days[cur.days.length - 1];
      if (cur && (d === last || d === nextDay(last!))) {
        if (d !== last) cur.days.push(d);
        cur.eventIds.push(e.eventIdentifier);
      } else {
        cur = { guestId15, site: siteFor(g, e.username), days: [d], eventIds: [e.eventIdentifier] };
        raw.push(cur);
      }
    }
  }
  return raw
    .filter((w) => !opts.event || w.eventIds.includes(opts.event))
    .sort((a, c) => a.days[0].localeCompare(c.days[0]) || a.site.localeCompare(c.site))
    .map((w, i) => ({ id: `W${i + 1}`, ...w }));
}

export function wavesFromWindow(days: string[], guests: GuestUser[]): Wave[] {
  return guests.filter((g) => g.active).map((g, i) => ({ id: `W${i + 1}`, guestId15: g.id15, site: siteFor(g, g.username), days, eventIds: [] }));
}

export const MAX_WINDOW_DAYS = 31;
const realDay = (d: string) => { const t = Date.parse(`${d}T00:00:00Z`); return !Number.isNaN(t) && new Date(t).toISOString().slice(0, 10) === d; };

export function parseDayWindow(spec: string): string[] {
  const m = /^(\d{4}-\d{2}-\d{2})\/(?:(\d{4}-\d{2}-\d{2})|P(\d+)D)$/.exec(spec.trim());
  if (!m) throw new Error(`--window must be YYYY-MM-DD/YYYY-MM-DD or YYYY-MM-DD/PnD, got "${spec}"`);
  const start = m[1];
  if (!realDay(start) || (m[2] && !realDay(m[2]))) throw new Error(`--window contains a date that does not exist (YYYY-MM-DD expected), got "${spec}"`);
  const spanDays = m[2] ? (Date.parse(`${m[2]}T00:00:00Z`) - Date.parse(`${start}T00:00:00Z`)) / 86_400_000 + 1 : Number(m[3]);
  if (spanDays < 1) throw new Error(`--window end must not be before its start, got "${spec}"`);
  if (spanDays > MAX_WINDOW_DAYS) throw new Error(`--window spans ${spanDays} days; the limit is ${MAX_WINDOW_DAYS}. Split it into several runs.`);
  const end = m[2] ?? new Date(Date.parse(`${start}T00:00:00Z`) + (spanDays - 1) * 86_400_000).toISOString().slice(0, 10);
  const out: string[] = [];
  for (let d = start; d <= end; d = nextDay(d)) out.push(d);
  return out;
}
