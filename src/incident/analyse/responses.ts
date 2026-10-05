import type { Bundle } from '../bundleIo.js';
import { DEFAULTS, id15, type Wave } from '../model.js';
import { baselineDaysFor, type Actor } from './actors.js';
import { classesOf, parseActions } from './actions.js';

export interface ReturnedContent {
  requestId: string;
  timestamp: string;
  ip: string;
  size: number;
  actions: string[];
  /** The actor block that sent the call, or '' when it came from no isolated block. */
  actorId: string;
}

export interface ResponseSummary {
  /**
   * Most common reply size in the reference set: the guest's auth replies on the wave days plus
   * its data-access replies on baseline days. Learned from replies that are NOT under test.
   */
  emptySize: number | null;
  /** True when the reference set was empty and the size was taken from the replies under test. */
  emptySizeInferred: boolean;
  band: number;
  /** All of the wave guest's data-access calls on the wave days, from any IP. */
  dataAccessCalls: number;
  /** Data-access and auth calls on the wave days whose REQUEST_ID joined to a Sites size. */
  joined: number;
  /** Data-access calls on the wave days whose REQUEST_ID joined to a Sites size. */
  dataAccessJoined: number;
  /** Replies in the reference set the empty size was learned from. */
  referenceReplies: number;
  returnedContent: ReturnedContent[];
  blankRequestIdsDropped: number;
  /** Data-access and auth calls on the wave days whose REQUEST_ID had no Sites size that day. */
  unmatchedCalls: number;  /** Guest controller calls on the wave days with an ACTION_MESSAGE that parsed to no action. */
  unparsedCalls: number;
}

const modeOf = (freq: Map<number, number>): number | undefined =>
  [...freq.entries()].sort((a, c) => c[1] - a[1] || a[0] - c[0])[0]?.[0];

/**
 * Joins AuraRequest to Sites on REQUEST_ID to get reply sizes. Sites repeats a request id
 * across rows, so it is reduced to one size (the maximum) per non-blank id BEFORE the join;
 * joining the raw rows multiplied one action's count into the millions. Blank ids are dropped:
 * as a key they would match every other blank (timeline/JoinKeys.ts rule).
 *
 * Every data-access call the wave guest made on the wave days is tested, whichever IP sent it:
 * an actor that rotates addresses never forms a block, and must still be assessed. The empty
 * size is learned from a separate reference set so a scanner receiving identical non-empty
 * replies cannot set its own "empty" baseline.
 */
export async function analyseResponses(b: Bundle, wave: Wave, actors: Actor[]): Promise<ResponseSummary> {
  const actorOf = new Map(actors.flatMap((a) => a.ips.map((ip) => [ip.trim().toLowerCase(), a.id] as const)));
  const out: ResponseSummary = {
    emptySize: null, emptySizeInferred: false, band: DEFAULTS.emptyBandBytes, dataAccessCalls: 0, joined: 0, dataAccessJoined: 0,
    referenceReplies: 0, returnedContent: [], blankRequestIdsDropped: 0, unmatchedCalls: 0, unparsedCalls: 0,
  };
  const isGuest = (r: Record<string, string>) => id15(r.USER_ID) === wave.guestId15 || id15(r.USER_ID_DERIVED) === wave.guestId15;
  const sizesFor = async (day: string, countBlanks: boolean): Promise<Map<string, number>> => {
    const sizes = new Map<string, number>();
    for await (const s of b.rows('Sites', day)) {
      const rid = (s.REQUEST_ID ?? '').trim();
      if (!rid) { if (countBlanks) out.blankRequestIdsDropped++; continue; }
      const n = Number(s.RESPONSE_SIZE || 0);
      if (n > (sizes.get(rid) ?? -1)) sizes.set(rid, n);
    }
    return sizes;
  };

  // Streamed: size frequency maps plus compact data-access candidates; no whole rows are kept.
  const reference = new Map<number, number>();
  const testedFreq = new Map<number, number>();
  const tested: ReturnedContent[] = [];
  for (const day of wave.days) {
    const sizes = await sizesFor(day, true);
    for await (const r of b.rows('AuraRequest', day)) {
      if (!r.ACTION_MESSAGE || !isGuest(r)) continue;
      if (parseActions(r.ACTION_MESSAGE).length === 0) { out.unparsedCalls++; continue; }
      const cls = classesOf(r.ACTION_MESSAGE);
      const dataAccess = cls.has('data-access');
      if (dataAccess) out.dataAccessCalls++;
      if (!dataAccess && !cls.has('auth')) continue;
      const requestId = (r.REQUEST_ID ?? '').trim();
      const size = sizes.get(requestId);
      if (size === undefined) { out.unmatchedCalls++; continue; }
      out.joined++;
      if (!dataAccess) { reference.set(size, (reference.get(size) ?? 0) + 1); continue; }
      out.dataAccessJoined++;
      testedFreq.set(size, (testedFreq.get(size) ?? 0) + 1);
      const ip = (r.CLIENT_IP ?? '').trim();
      tested.push({ requestId, timestamp: r.TIMESTAMP_DERIVED, ip, size, actions: parseActions(r.ACTION_MESSAGE), actorId: actorOf.get(ip.toLowerCase()) ?? '' });
    }
  }
  for (const day of baselineDaysFor(b.manifest, wave.guestId15)) {
    const sizes = await sizesFor(day, false);
    for await (const r of b.rows('AuraRequest', day)) {
      if (!r.ACTION_MESSAGE || !isGuest(r) || !classesOf(r.ACTION_MESSAGE).has('data-access')) continue;
      const size = sizes.get((r.REQUEST_ID ?? '').trim());
      if (size !== undefined) reference.set(size, (reference.get(size) ?? 0) + 1);
    }
  }
  out.referenceReplies = [...reference.values()].reduce((s, n) => s + n, 0);

  let mode = modeOf(reference);
  if (mode === undefined && tested.length > 0) {
    mode = modeOf(testedFreq);
    out.emptySizeInferred = true;
  }
  if (mode === undefined) return out;
  out.emptySize = mode;
  out.returnedContent = tested
    .filter((s) => s.size > mode + out.band)
    .sort((a, c) => a.timestamp.localeCompare(c.timestamp));
  return out;
}
