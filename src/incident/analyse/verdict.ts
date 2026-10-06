// src/incident/analyse/verdict.ts
import type { BundleManifest, Classification, FollowUp, Wave, WaveOutcome } from '../model.js';
import type { Actor } from './actors.js';
import type { SpikeAssessment } from './baseline.js';
import type { Asymmetry } from './configDelta.js';
import type { Outcomes } from './outcomes.js';
import type { ResponseSummary } from './responses.js';

export interface VerdictInput {
  wave: Wave;
  spikes: SpikeAssessment[];
  actors: Actor[];
  responses: ResponseSummary;
  outcomes: Outcomes;
  requiredLogsPresent: boolean;
}

export const FORBIDDEN_WORDS = /\b(attack|breach)\w*/i;

export function isScannerLike(a: Actor): boolean {
  return a.steady && (a.markers.length > 0 || a.emptyUaShare > 0.5);
}

export function classify(v: VerdictInput): Classification {
  if (v.outcomes.identityLinks.length > 0) return 'internal-testing';
  if (v.actors.some(isScannerLike)) return 'automated-scan';
  // Organic needs a spike with no isolated source AND nothing returned: content returned to
  // unattributed traffic is not shown to be organic.
  if (v.spikes.some((s) => s.isSpike) && v.actors.length === 0 && v.responses.returnedContent.length === 0 && notAssessedReasons(v).length === 0) return 'organic';
  return 'indeterminate';
}

/**
 * Why a wave cannot be called no-evidence. No-evidence is allowed only when this is empty:
 * the required logs are present, the empty-reply size came from a reference set, every
 * controller call parsed, EVERY data-access call was joined to a reply size (any unjoined read
 * could be the one that returned content), and every wave day has a baseline median.
 * The join test uses data-access joins, not all joins: a joined auth reply says nothing about
 * what a data read returned (stricter than `joined > 0`).
 */
export function notAssessedReasons(v: VerdictInput): string[] {
  const out: string[] = [];
  if (!v.requiredLogsPresent) out.push('AuraRequest or Sites logs were not collected for every wave day');
  if (v.responses.emptySizeInferred) out.push('the empty-reply size could only be inferred from the replies under test');
  const { dataAccessCalls, dataAccessJoined, unparsedCalls } = v.responses;
  if (unparsedCalls > 0) out.push(`${unparsedCalls} controller calls could not be parsed, so what they did is unknown`);
  if (dataAccessJoined < dataAccessCalls) {
    out.push(dataAccessJoined === 0
      ? `none of the ${dataAccessCalls} data-access calls could be joined to a reply size`
      : `only ${dataAccessJoined} of ${dataAccessCalls} data-access calls could be joined to a reply size`);
  }
  const contextual = v.responses.returnedContent.length - decisiveReturned(v).length;
  if (contextual > 0) out.push(`${contextual} replies to other guest traffic returned content that cannot be ruled out as the actor's`);
  if (v.outcomes.sharedEgressLogins > 0) out.push(`${v.outcomes.sharedEgressLogins} successful logins from shared actor IPs could not be attributed`);
  if (!v.spikes.every((s) => s.baselineMedian !== null)) out.push('no baseline day was collected, so wave-day volume could not be compared');
  return out;
}

/**
 * Returned content that decides the result. With an isolated actor, only the actor's replies
 * count: a public site returns content to its ordinary visitors all the time. Without one,
 * every guest reply counts, because nothing separates the actor from the visitors.
 */
export function decisiveReturned(v: VerdictInput): ResponseSummary['returnedContent'] {
  const all = v.responses.returnedContent;
  if (v.actors.length === 0) return all;
  // An attacker can read from addresses outside its block. Non-actor content is only context
  // when its action is ordinary traffic: seen on baseline days from blocks absent on the wave days.
  const normal = new Set(v.responses.baselineActions);
  return all.filter((x) => x.actorId !== '' || !normal.has(x.action));
}

/** Precedence: access-gained > content-returned > not-assessed > no-evidence. */
export function outcomeOf(v: VerdictInput): WaveOutcome {
  if (v.outcomes.successfulLogins > 0) return 'access-gained';
  if (decisiveReturned(v).length > 0) return 'content-returned';
  if (notAssessedReasons(v).length > 0) return 'not-assessed';
  return 'no-evidence';
}

/** Org-wide limits: they hold for the whole report, including one with zero waves. */
export function globalLimitsFor(m: BundleManifest, followUp?: FollowUp): string[] {
  const out: string[] = [
    'Guest traffic carries no identity: activity by one person behind a shared proxy or NAT is only visible if it lifts that block well above its own history; a slow probe inside normal proxy volume cannot be seen in these logs.',
  ];
  if (!m.detectorAvailable) out.push('Guest User Anomaly events were not available; waves come from the supplied window only.');
  if (m.audit.inaccessible) out.push('The setup audit trail could not be read, so configuration changes are unknown.');
  if (m.audit.truncatedWindows.length > 0) out.push(`The setup audit trail was truncated for ${m.audit.truncatedWindows.length} window(s); some changes may be missing.`);
  if (m.ipRangeFiles.length === 0) out.push('Hosting provider not assessed: no --ip-ranges files were supplied.');
  if (!m.limits.queryAllFiles) out.push('The collecting user lacks Query All Files, so files owned by or shared with guest users were not checked.');
  if (!m.limits.viewAllData) out.push('The collecting user lacks View All Data, so record visibility checks are partial.');
  for (const w of m.snapshotWarnings ?? []) out.push(`Guest configuration was read only in part: ${w}`);
  if (followUp?.truncated) out.push('Login history for actor IPs was truncated at 10,000 rows per batch; some logins may be missing.');
  return out;
}

/** Limits specific to one wave. Org-wide limits live in globalLimitsFor. */
export function limitsFor(v: VerdictInput): string[] {
  const out = ['Response bodies are never logged by Salesforce, so the content of any reply is unknown; only its size is.'];
  if (outcomeOf(v) === 'not-assessed') out.push(`Not assessed: ${notAssessedReasons(v).join('; ')}.`);
  if (!v.requiredLogsPresent) out.push(`AuraRequest or Sites logs were not collected for ${v.wave.days.join(', ')}, so reply sizes could not be assessed.`);
  if (v.actors.some((a) => !a.hostingAssessed && a.block.includes(':'))) out.push('Hosting provider not assessed for IPv6 addresses.');
  if (v.actors.length === 0 && (v.spikes.some((s) => s.isSpike) || v.wave.eventIds.length > 0)) {
    out.push('No single source block was isolated; reply sizes were assessed across all guest traffic on the wave days.');
  }
  if (v.responses.emptySizeInferred) {
    out.push('The empty-reply size was inferred from the replies being tested; a scanner receiving identical non-empty replies would not be detected.');
  }
  if (v.outcomes.selfRegistrationsInActorWindow.length > 0) out.push('Self-registrations occurred during the actor window; the audit trail records no IP, so they cannot be attributed.');
  if (v.responses.unparsedCalls > 0) out.push(`${v.responses.unparsedCalls} controller calls could not be parsed; their nature is unknown.`);
  const contextual = v.responses.returnedContent.length - decisiveReturned(v).length;
  if (contextual > 0) out.push(`${contextual} replies to other guest traffic on the wave days were larger than empty; a public site returns content to its visitors, so these are listed in the evidence but do not decide the result.`);
  if (v.responses.judgedAgainstFallback > 0 && v.responses.emptySize !== null) {
    out.push(`${v.responses.judgedAgainstFallback} data-access calls were judged against the site-wide reference size of ${v.responses.emptySize} bytes because their action had no empty size of its own; smaller non-empty replies may have been missed.`);
  }
  if (v.responses.ambiguousCalls > 0) out.push(`${v.responses.ambiguousCalls} calls shared a request id with other rows, so their reply sizes could not be told apart.`);
  if (v.responses.unmatchedCalls > 0) out.push(`${v.responses.unmatchedCalls} data-access or auth calls had no matching Sites row; their reply sizes are unknown.`);
  const sharedIps = v.actors.flatMap((a) => a.sharedEgressIps);
  if (sharedIps.length > 0) {
    out.push(`${sharedIps.length} actor IP(s) are shared by many users (a proxy or NAT): ${v.outcomes.sharedEgressLogins} logins from them are not counted as access, and one person's activity behind them cannot be separated in these logs.`);
  }
  if (v.outcomes.identityLinks.length > 0 && v.actors.some(isScannerLike)) out.push('An identity link and scanner-like traffic were both seen; the link alone does not show the traffic was authorised.');
  return out;
}

export function nextStepsFor(v: VerdictInput, asymmetries: Asymmetry[], m: BundleManifest): string[] {
  const steps: string[] = [];
  const days = v.wave.days.join(', ');
  for (const a of v.actors) {
    if (isScannerLike(a)) steps.push(`Confirm with your security team whether an authorised test ran on ${days} from ${a.block}${a.hosting ? ` (${a.hosting})` : ''}. If none did, treat this as an incident.`);
  }
  const decisive = decisiveReturned(v).length;
  if (decisive > 0) steps.push(`Replay the ${decisive} data-access calls that returned content, as the guest user, to establish what they returned.`);
  for (const l of v.outcomes.identityLinks) steps.push(`Confirm the testing with ${l.userName} (${l.email}); deactivate that user if the test is complete.`);
  for (const s of asymmetries) steps.push(`Review whether the ${s.comparedChanges} guest-access changes made to ${s.comparedSite} between waves should also apply to ${s.site}.`);
  if (!m.limits.queryAllFiles) steps.push('Re-run collection as a user with Query All Files to check guest-owned files.');
  return steps;
}
