// test/unit/incident/verdict.test.ts
import { describe, it, expect } from '@jest/globals';
import { classify, globalLimitsFor, outcomeOf, limitsFor, nextStepsFor, type VerdictInput } from '../../../src/incident/analyse/verdict.js';
import type { BundleManifest } from '../../../src/incident/model.js';

const base: VerdictInput = {
  wave: { id: 'W1', guestId15: 'g', site: 'S', days: ['2026-01-02'], eventIds: [] },
  spikes: [{ day: '2026-01-02', controllerCalls: 10, baselineMedian: 10, ratio: 1, isSpike: false, detectorSample: null }],
  actors: [],
  responses: { emptySize: null, emptySizeInferred: false, band: 64, dataAccessCalls: 0, joined: 0, dataAccessJoined: 0, referenceReplies: 0, unmatchedCalls: 0, unparsedCalls: 0, returnedContent: [], blankRequestIdsDropped: 0 },
  outcomes: { actorLogins: [], successfulLogins: 0, failedLogins: 0, selfRegistrationsInActorWindow: [], identityLinks: [] },
  requiredLogsPresent: true,
};
const manifest = { limits: { queryAllFiles: true, viewAllData: true }, ipRangeFiles: [], detectorAvailable: true, audit: { truncatedWindows: [], inaccessible: false }, logs: [] } as unknown as BundleManifest;

describe('verdict', () => {
  it('is not-assessed (never no-evidence) when required logs are missing', () => {
    expect(outcomeOf({ ...base, requiredLogsPresent: false })).toBe('not-assessed');
    expect(limitsFor({ ...base, requiredLogsPresent: false }).join(' ')).toMatch(/not collected/);
  });
  it('is indeterminate with no actors and no spike', () => {
    expect(classify(base)).toBe('indeterminate');
  });
  it('is organic for a spike with no actor blocks', () => {
    expect(classify({ ...base, spikes: [{ ...base.spikes[0], isSpike: true, ratio: 9 }] })).toBe('organic');
  });
  it('C2: is indeterminate, not organic, for an actor-less spike that returned content', () => {
    const v = { ...base, spikes: [{ ...base.spikes[0], isSpike: true, ratio: 9 }], responses: { ...base.responses, returnedContent: [{} as never] } };
    expect(classify(v)).toBe('indeterminate');
  });
  it('C2: states that no source block was isolated for a spike or detector event without actors', () => {
    const msg = 'No single source block was isolated; reply sizes were assessed across all guest traffic on the wave days.';
    expect(limitsFor({ ...base, spikes: [{ ...base.spikes[0], isSpike: true, ratio: 9 }] })).toContain(msg);
    expect(limitsFor({ ...base, wave: { ...base.wave, eventIds: ['e1'] } })).toContain(msg);
    expect(limitsFor(base)).not.toContain(msg);
  });
  it('always states that response bodies are never logged', () => {
    expect(limitsFor(base).join(' ')).toMatch(/bodies are never logged/);
  });
});

const scanner = { id: 'a1', block: '203.0.113.0/24', ips: ['203.0.113.1'], steady: true, markers: ['log4shell'], emptyUaShare: 0, hosting: null, hostingAssessed: true } as unknown as VerdictInput['actors'][number];
const link = { ip: '203.0.113.1', userId15: 'u', userName: 'u@example.com', email: 'u@example.com', userCreatedDate: '', createdByGuest: 'g', loginTime: '' };

describe('verdict precedence and caveats', () => {
  it('reports access-gained even when required logs are missing', () => {
    expect(outcomeOf({ ...base, requiredLogsPresent: false, outcomes: { ...base.outcomes, successfulLogins: 1 } })).toBe('access-gained');
  });
  it('reports content-returned even when required logs are missing', () => {
    expect(outcomeOf({ ...base, requiredLogsPresent: false, responses: { ...base.responses, returnedContent: [{} as never] } })).toBe('content-returned');
  });
  it('keeps the scanner step and caveat when an identity link coexists', () => {
    const v: VerdictInput = { ...base, actors: [scanner], outcomes: { ...base.outcomes, identityLinks: [link] } };
    expect(classify(v)).toBe('internal-testing');
    expect(nextStepsFor(v, [], manifest).join(' ')).toMatch(/treat this as an incident/);
    expect(limitsFor(v).join(' ')).toMatch(/link alone does not show/);
  });
  it('C3: states how many controller calls could not be parsed', () => {
    expect(limitsFor({ ...base, responses: { ...base.responses, unparsedCalls: 4 } })).toContain('4 controller calls could not be parsed; their nature is unknown.');
    expect(limitsFor(base).join(' ')).not.toMatch(/could not be parsed/);
  });
  it('states unmatched call counts', () => {
    expect(limitsFor({ ...base, responses: { ...base.responses, unmatchedCalls: 3 } }).join(' ')).toMatch(/3 data-access or auth calls had no matching Sites row/);
  });
});

describe('the no-evidence invariant', () => {
  const nullBase = { ...base.spikes[0], baselineMedian: null, ratio: null };
  it('allows no-evidence only when every condition holds', () => {
    expect(outcomeOf(base)).toBe('no-evidence');
    expect(limitsFor(base).join(' ')).not.toMatch(/Not assessed/);
  });
  it('is not-assessed when required logs are missing, and says why', () => {
    const v = { ...base, requiredLogsPresent: false };
    expect(outcomeOf(v)).toBe('not-assessed');
    expect(limitsFor(v).join(' ')).toMatch(/Not assessed: AuraRequest or Sites logs were not collected for every wave day/);
  });
  it('is not-assessed when the empty-reply size was inferred, and says why', () => {
    const v = { ...base, responses: { ...base.responses, emptySizeInferred: true, emptySize: 5000, dataAccessCalls: 9, joined: 9, dataAccessJoined: 9 } };
    expect(outcomeOf(v)).toBe('not-assessed');
    expect(limitsFor(v).join(' ')).toMatch(/Not assessed: the empty-reply size could only be inferred from the replies under test/);
  });
  it('is not-assessed when data-access calls exist but none joined to a reply size, and says why', () => {
    const v = { ...base, responses: { ...base.responses, dataAccessCalls: 5, joined: 0, dataAccessJoined: 0, unmatchedCalls: 5 } };
    expect(outcomeOf(v)).toBe('not-assessed');
    expect(limitsFor(v).join(' ')).toMatch(/Not assessed: none of the 5 data-access calls could be joined to a reply size/);
  });
  it('is not-assessed when only auth calls joined and every data-access call is unmatched (conservative)', () => {
    const v = { ...base, responses: { ...base.responses, dataAccessCalls: 5, joined: 3, dataAccessJoined: 0, unmatchedCalls: 5 } };
    expect(outcomeOf(v)).toBe('not-assessed');
  });
  it('is not-assessed when a wave day has no baseline median, and says why', () => {
    const v = { ...base, spikes: [nullBase] };
    expect(outcomeOf(v)).toBe('not-assessed');
    expect(limitsFor(v).join(' ')).toMatch(/Not assessed: no baseline day was collected, so wave-day volume could not be compared/);
  });
  it('keeps the precedence access-gained > content-returned > not-assessed', () => {
    const v = { ...base, spikes: [nullBase], responses: { ...base.responses, emptySizeInferred: true } };
    expect(outcomeOf({ ...v, responses: { ...v.responses, returnedContent: [{} as never] } })).toBe('content-returned');
    expect(outcomeOf({ ...v, outcomes: { ...v.outcomes, successfulLogins: 1 } })).toBe('access-gained');
    expect(limitsFor({ ...v, outcomes: { ...v.outcomes, successfulLogins: 1 } }).join(' ')).not.toMatch(/Not assessed:/);
  });
});

describe('globalLimitsFor', () => {
  it('I4: states that login history for actor IPs was truncated', () => {
    const msg = 'Login history for actor IPs was truncated at 10,000 rows per batch; some logins may be missing.';
    expect(globalLimitsFor(manifest, { logins: [], users: [], truncated: true })).toContain(msg);
    expect(globalLimitsFor(manifest, { logins: [], users: [] })).not.toContain(msg);
  });
});

describe('globalLimitsFor snapshot warnings (M2)', () => {
  it('states each degraded snapshot read', () => {
    const m = { ...manifest, snapshotWarnings: ['Could not read Site (INVALID_TYPE); continuing without it.'] } as BundleManifest;
    expect(globalLimitsFor(m).join(' ')).toContain('Guest configuration was read only in part: Could not read Site (INVALID_TYPE); continuing without it.');
    expect(globalLimitsFor(manifest).join(' ')).not.toMatch(/read only in part/);
  });
});

describe('residual 3: no-evidence needs every call understood and every data read joined', () => {
  const assessed = { ...base.responses, emptySize: 1861, referenceReplies: 40 };
  it('is no-evidence when all 20 data-access calls joined, none returned content, and nothing was unparsed', () => {
    expect(outcomeOf({ ...base, responses: { ...assessed, dataAccessCalls: 20, joined: 20, dataAccessJoined: 20 } })).toBe('no-evidence');
  });
  it('is not-assessed when any controller call could not be parsed, even with no data-access calls', () => {
    const v = { ...base, responses: { ...assessed, unparsedCalls: 198 } };
    expect(outcomeOf(v)).toBe('not-assessed');
    expect(limitsFor(v).join(' ')).toMatch(/198 controller calls could not be parsed/);
  });
  it('is not-assessed when any data-access call could not be joined to a reply size', () => {
    const v = { ...base, responses: { ...assessed, dataAccessCalls: 198, joined: 191, dataAccessJoined: 191, unmatchedCalls: 7 } };
    expect(outcomeOf(v)).toBe('not-assessed');
    expect(limitsFor(v).join(' ')).toMatch(/only 191 of 198 data-access calls could be joined/);
  });
  it('is not-assessed even when a single data-access call is unjoined', () => {
    expect(outcomeOf({ ...base, responses: { ...assessed, dataAccessCalls: 20, joined: 19, dataAccessJoined: 19, unmatchedCalls: 1 } })).toBe('not-assessed');
  });
});
