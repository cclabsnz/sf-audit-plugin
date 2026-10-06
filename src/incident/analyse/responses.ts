import type { Bundle } from '../bundleIo.js';
import { DEFAULTS, id15, type Wave } from '../model.js';
import { baselineDaysFor, blockOf, normaliseIp, type Actor } from './actors.js';
import { classesOf, classifyAction, parseActions } from './actions.js';

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
   * its data-access replies on baseline days, excluding blocks also active on the wave days.
   * Learned from replies that are NOT under test.
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
  unmatchedCalls: number;  /** Data-access and auth calls whose REQUEST_ID was shared with other rows, so never joined. */
  ambiguousCalls: number;
  /** Empty-reply size learned per action from the reference set (smallest recurring size). */
  emptySizeByAction: Record<string, number>;
  /** Joined data-access calls whose action had no empty size of its own, judged against emptySize. */
  judgedAgainstFallback: number;
  /** Guest controller calls on the wave days with an ACTION_MESSAGE that parsed to no action. */
  unparsedCalls: number;
}

/** Smallest size seen at least max(3, 5% of the action's replies) times. */
function smallestRecurring(freq: Map<number, number>): number | undefined {
  const total = [...freq.values()].reduce((a, n) => a + n, 0);
  const min = Math.max(3, Math.ceil(total * 0.05));
  return [...freq.entries()].filter(([, n]) => n >= min).map(([size]) => size).sort((a, c) => a - c)[0];
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
  const actorOf = new Map(actors.flatMap((a) => a.ips.map((ip) => [normaliseIp(ip), a.id] as const)));
  const out: ResponseSummary = {
    emptySize: null, emptySizeInferred: false, band: DEFAULTS.emptyBandBytes, dataAccessCalls: 0, joined: 0, dataAccessJoined: 0,
    referenceReplies: 0, returnedContent: [], blankRequestIdsDropped: 0, unmatchedCalls: 0, unparsedCalls: 0,
    ambiguousCalls: 0, emptySizeByAction: {}, judgedAgainstFallback: 0,
  };
  const isGuest = (r: Record<string, string>) => id15(r.USER_ID) === wave.guestId15 || id15(r.USER_ID_DERIVED) === wave.guestId15;
  /**
   * Reply sizes by REQUEST_ID for one day, joinable only when unambiguous: the id belongs to
   * exactly one AuraRequest row and at most two Sites rows. On some sites one id is reused
   * across hundreds of calls, and taking its largest Sites row would give every call that size.
   */
  const repliesFor = async (day: string, countBlanks: boolean): Promise<(rid: string) => number | 'ambiguous' | undefined> => {
    const sizes = new Map<string, number>();
    const sitesRows = new Map<string, number>();
    for await (const s of b.rows('Sites', day)) {
      const rid = (s.REQUEST_ID ?? '').trim();
      if (!rid) { if (countBlanks) out.blankRequestIdsDropped++; continue; }
      sitesRows.set(rid, (sitesRows.get(rid) ?? 0) + 1);
      const n = Number(s.RESPONSE_SIZE || 0);
      if (n > (sizes.get(rid) ?? -1)) sizes.set(rid, n);
    }
    const auraRows = new Map<string, number>();
    for await (const r of b.rows('AuraRequest', day)) {
      const rid = (r.REQUEST_ID ?? '').trim();
      if (rid) auraRows.set(rid, (auraRows.get(rid) ?? 0) + 1);
    }
    return (rid) => {
      const size = sizes.get(rid);
      if (size === undefined) return undefined;
      return (auraRows.get(rid) ?? 0) > 1 || (sitesRows.get(rid) ?? 0) > 2 ? 'ambiguous' : size;
    };
  };
  const bump = (m: Map<string, Map<number, number>>, key: string, size: number) => {
    let f = m.get(key);
    if (!f) { f = new Map(); m.set(key, f); }
    f.set(size, (f.get(size) ?? 0) + 1);
  };
  /** The action a reply is attributed to: the batch's first data-access action, else its first auth action. */
  const primaryAction = (msg: string, dataAccess: boolean): string =>
    parseActions(msg).find((n) => classifyAction(n) === (dataAccess ? 'data-access' : 'auth')) ?? '';

  // Streamed: size frequency maps plus compact data-access candidates; no whole rows are kept.
  const reference = new Map<number, number>();
  const referenceByAction = new Map<string, Map<number, number>>();
  const testedFreq = new Map<number, number>();
  const tested: Array<ReturnedContent & { action: string }> = [];
  // Blocks that sent guest controller calls on the wave days. Their baseline-day replies are
  // left out of the reference set: a scan that runs past midnight would otherwise set its own
  // "empty" size from the next day's replies.
  const waveBlocks = new Set<string>();
  for (const day of wave.days) {
    const replyOf = await repliesFor(day, true);
    for await (const r of b.rows('AuraRequest', day)) {
      if (!r.ACTION_MESSAGE || !isGuest(r)) continue;
      waveBlocks.add(blockOf(normaliseIp(r.CLIENT_IP ?? '')));
      if (parseActions(r.ACTION_MESSAGE).length === 0) { out.unparsedCalls++; continue; }
      const cls = classesOf(r.ACTION_MESSAGE);
      const dataAccess = cls.has('data-access');
      if (dataAccess) out.dataAccessCalls++;
      if (!dataAccess && !cls.has('auth')) continue;
      const requestId = (r.REQUEST_ID ?? '').trim();
      const size = replyOf(requestId);
      if (size === undefined) { out.unmatchedCalls++; continue; }
      if (size === 'ambiguous') { out.ambiguousCalls++; continue; }
      out.joined++;
      const action = primaryAction(r.ACTION_MESSAGE, dataAccess);
      if (!dataAccess) {
        reference.set(size, (reference.get(size) ?? 0) + 1);
        bump(referenceByAction, action, size);
        continue;
      }
      out.dataAccessJoined++;
      testedFreq.set(size, (testedFreq.get(size) ?? 0) + 1);
      const ip = normaliseIp(r.CLIENT_IP ?? '');
      // Ordinary visitors' replies teach each action's smallest recurring size (an empty list).
      // An actor cannot lower that floor, and its own replies are never part of it.
      if (!actorOf.has(ip)) bump(referenceByAction, action, size);
      tested.push({ requestId, timestamp: r.TIMESTAMP_DERIVED, ip, size, actions: parseActions(r.ACTION_MESSAGE), actorId: actorOf.get(ip) ?? '', action });
    }
  }
  for (const day of baselineDaysFor(b.manifest, wave.guestId15)) {
    const replyOf = await repliesFor(day, false);
    for await (const r of b.rows('AuraRequest', day)) {
      if (!r.ACTION_MESSAGE || !isGuest(r) || !classesOf(r.ACTION_MESSAGE).has('data-access')) continue;
      if (waveBlocks.has(blockOf(normaliseIp(r.CLIENT_IP ?? '')))) continue;
      const size = replyOf((r.REQUEST_ID ?? '').trim());
      if (typeof size !== 'number') continue;
      reference.set(size, (reference.get(size) ?? 0) + 1);
      bump(referenceByAction, primaryAction(r.ACTION_MESSAGE, true), size);
    }
  }
  out.referenceReplies = [...reference.values()].reduce((s, n) => s + n, 0);

  // Per action, the empty reply is the SMALLEST size that recurs (an empty list), not the most
  // common one: legitimate reads on baseline days return data, so their mode is not "empty".
  for (const [action, freq] of referenceByAction) {
    const size = smallestRecurring(freq);
    if (action && size !== undefined) out.emptySizeByAction[action] = size;
  }
  let mode = modeOf(reference);
  if (mode === undefined && tested.length > 0) {
    mode = modeOf(testedFreq);
    out.emptySizeInferred = true;
  }
  if (mode === undefined) return out;
  out.emptySize = mode;
  const fallback = mode;
  out.judgedAgainstFallback = tested.filter((s) => out.emptySizeByAction[s.action] === undefined).length;
  out.returnedContent = tested
    .filter((s) => s.size > (out.emptySizeByAction[s.action] ?? fallback) + out.band)
    .map(({ action: _action, ...rest }) => rest)
    .sort((a, c) => a.timestamp.localeCompare(c.timestamp));
  return out;
}
