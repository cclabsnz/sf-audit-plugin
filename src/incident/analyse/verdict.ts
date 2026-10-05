// src/incident/analyse/verdict.ts
import type { BundleManifest, Classification, Wave, WaveOutcome } from '../model.js';
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
  if (v.spikes.some((s) => s.isSpike) && v.actors.length === 0 && v.responses.returnedContent.length === 0) return 'organic';
  return 'indeterminate';
}

export function outcomeOf(v: VerdictInput): WaveOutcome {
  if (v.outcomes.successfulLogins > 0) return 'access-gained';
  if (v.responses.returnedContent.length > 0) return 'content-returned';
  if (!v.requiredLogsPresent) return 'not-assessed';
  return 'no-evidence';
}

/** Org-wide limits: they hold for the whole report, including one with zero waves. */
export function globalLimitsFor(m: BundleManifest): string[] {
  const out: string[] = [];
  if (!m.detectorAvailable) out.push('Guest User Anomaly events were not available; waves come from the supplied window only.');
  if (m.audit.inaccessible) out.push('The setup audit trail could not be read, so configuration changes are unknown.');
  if (m.audit.truncatedWindows.length > 0) out.push(`The setup audit trail was truncated for ${m.audit.truncatedWindows.length} window(s); some changes may be missing.`);
  if (m.ipRangeFiles.length === 0) out.push('Hosting provider not assessed: no --ip-ranges files were supplied.');
  if (!m.limits.queryAllFiles) out.push('The collecting user lacks Query All Files, so files owned by or shared with guest users were not checked.');
  if (!m.limits.viewAllData) out.push('The collecting user lacks View All Data, so record visibility checks are partial.');
  return out;
}

/** Limits specific to one wave. Org-wide limits live in globalLimitsFor. */
export function limitsFor(v: VerdictInput): string[] {
  const out = ['Response bodies are never logged by Salesforce, so the content of any reply is unknown; only its size is.'];
  if (!v.requiredLogsPresent) out.push(`AuraRequest or Sites logs were not collected for ${v.wave.days.join(', ')}, so reply sizes could not be assessed.`);
  if (v.actors.some((a) => !a.hostingAssessed && a.block.includes(':'))) out.push('Hosting provider not assessed for IPv6 addresses.');
  if (v.actors.length === 0 && (v.spikes.some((s) => s.isSpike) || v.wave.eventIds.length > 0)) {
    out.push('No single source block was isolated; reply sizes were assessed across all guest traffic on the wave days.');
  }
  if (v.responses.emptySizeInferred) {
    out.push('The empty-reply size was inferred from the replies being tested; a scanner receiving identical non-empty replies would not be detected.');
  }
  if (v.outcomes.selfRegistrationsInActorWindow.length > 0) out.push('Self-registrations occurred during the actor window; the audit trail records no IP, so they cannot be attributed.');
  if (v.responses.unmatchedCalls > 0) out.push(`${v.responses.unmatchedCalls} data-access or auth calls had no matching Sites row; their reply sizes are unknown.`);
  if (v.outcomes.identityLinks.length > 0 && v.actors.some(isScannerLike)) out.push('An identity link and scanner-like traffic were both seen; the link alone does not show the traffic was authorised.');
  return out;
}

export function nextStepsFor(v: VerdictInput, asymmetries: Asymmetry[], m: BundleManifest): string[] {
  const steps: string[] = [];
  const days = v.wave.days.join(', ');
  for (const a of v.actors) {
    if (isScannerLike(a)) steps.push(`Confirm with your security team whether an authorised test ran on ${days} from ${a.block}${a.hosting ? ` (${a.hosting})` : ''}. If none did, treat this as an incident.`);
  }
  if (v.responses.returnedContent.length > 0) steps.push(`Replay the ${v.responses.returnedContent.length} data-access calls that returned content, as the guest user, to establish what they returned.`);
  for (const l of v.outcomes.identityLinks) steps.push(`Confirm the testing with ${l.userName} (${l.email}); deactivate that user if the test is complete.`);
  for (const s of asymmetries) steps.push(`Review whether the ${s.comparedChanges} guest-access changes made to ${s.comparedSite} between waves should also apply to ${s.site}.`);
  if (!m.limits.queryAllFiles) steps.push('Re-run collection as a user with Query All Files to check guest-owned files.');
  return steps;
}
