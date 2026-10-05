// test/unit/incident/verdict.test.ts
import { describe, it, expect } from '@jest/globals';
import { classify, outcomeOf, limitsFor, nextStepsFor, type VerdictInput } from '../../../src/incident/analyse/verdict.js';
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
