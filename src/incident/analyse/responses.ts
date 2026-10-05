import type { Bundle } from '../bundleIo.js';
import { DEFAULTS, id15, type Wave } from '../model.js';
import type { Actor } from './actors.js';
import { classesOf, parseActions } from './actions.js';

export interface ReturnedContent { requestId: string; timestamp: string; ip: string; size: number; actions: string[] }

export interface ResponseSummary {
  /** Most common reply size among the actors' auth and data-access calls: an empty envelope. */
  emptySize: number | null;
  band: number;
  dataAccessCalls: number;
  joined: number;
  returnedContent: ReturnedContent[];
  blankRequestIdsDropped: number;
}

/**
 * Joins AuraRequest to Sites on REQUEST_ID to get reply sizes. Sites repeats a request id
 * across rows, so it is reduced to one size (the maximum) per non-blank id BEFORE the join;
 * joining the raw rows multiplied one action's count into the millions. Blank ids are dropped:
 * as a key they would match every other blank (timeline/JoinKeys.ts rule).
 */
export async function analyseResponses(b: Bundle, wave: Wave, actors: Actor[]): Promise<ResponseSummary> {
  const actorIps = new Set(actors.flatMap((a) => a.ips));
  const out: ResponseSummary = { emptySize: null, band: DEFAULTS.emptyBandBytes, dataAccessCalls: 0, joined: 0, returnedContent: [], blankRequestIdsDropped: 0 };
  if (actorIps.size === 0) return out;

  const samples: Array<{ size: number; dataAccess: boolean; row: Record<string, string> }> = [];
  for (const day of wave.days) {
    const sizes = new Map<string, number>();
    for await (const s of b.rows('Sites', day)) {
      const rid = (s.REQUEST_ID ?? '').trim();
      if (!rid) { out.blankRequestIdsDropped++; continue; }
      const n = Number(s.RESPONSE_SIZE || 0);
      if (n > (sizes.get(rid) ?? -1)) sizes.set(rid, n);
    }
    for await (const r of b.rows('AuraRequest', day)) {
      if (!actorIps.has((r.CLIENT_IP ?? '').trim()) || !r.ACTION_MESSAGE) continue;
      if (id15(r.USER_ID) !== wave.guestId15 && id15(r.USER_ID_DERIVED) !== wave.guestId15) continue;
      const cls = classesOf(r.ACTION_MESSAGE);
      const dataAccess = cls.has('data-access');
      if (dataAccess) out.dataAccessCalls++;
      if (!dataAccess && !cls.has('auth')) continue;
      const size = sizes.get((r.REQUEST_ID ?? '').trim());
      if (size === undefined) continue;
      out.joined++;
      samples.push({ size, dataAccess, row: r });
    }
  }

  const freq = new Map<number, number>();
  for (const s of samples) freq.set(s.size, (freq.get(s.size) ?? 0) + 1);
  const mode = [...freq.entries()].sort((a, c) => c[1] - a[1] || a[0] - c[0])[0]?.[0];
  if (mode === undefined) return out;
  out.emptySize = mode;
  out.returnedContent = samples
    .filter((s) => s.dataAccess && s.size > mode + out.band)
    .map((s) => ({ requestId: s.row.REQUEST_ID, timestamp: s.row.TIMESTAMP_DERIVED, ip: s.row.CLIENT_IP, size: s.size, actions: parseActions(s.row.ACTION_MESSAGE) }))
    .sort((a, c) => a.timestamp.localeCompare(c.timestamp));
  return out;
}
