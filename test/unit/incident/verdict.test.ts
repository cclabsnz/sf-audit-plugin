// test/unit/incident/verdict.test.ts
import { describe, it, expect } from '@jest/globals';
import { classify, outcomeOf, limitsFor, type VerdictInput } from '../../../src/incident/analyse/verdict.js';
import type { BundleManifest } from '../../../src/incident/model.js';

const base: VerdictInput = {
  wave: { id: 'W1', guestId15: 'g', site: 'S', days: ['2026-01-02'], eventIds: [] },
  spikes: [{ day: '2026-01-02', controllerCalls: 10, baselineMedian: 10, ratio: 1, isSpike: false, detectorSample: null }],
  actors: [],
  responses: { emptySize: null, band: 64, dataAccessCalls: 0, joined: 0, unmatchedCalls: 0, returnedContent: [], blankRequestIdsDropped: 0 },
  outcomes: { actorLogins: [], successfulLogins: 0, failedLogins: 0, selfRegistrationsInActorWindow: [], identityLinks: [] },
  requiredLogsPresent: true,
};
const manifest = { limits: { queryAllFiles: true, viewAllData: true }, ipRangeFiles: [], detectorAvailable: true, audit: { truncatedWindows: [], inaccessible: false }, logs: [] } as unknown as BundleManifest;

describe('verdict', () => {
  it('is not-assessed (never no-evidence) when required logs are missing', () => {
    expect(outcomeOf({ ...base, requiredLogsPresent: false })).toBe('not-assessed');
    expect(limitsFor({ ...base, requiredLogsPresent: false }, manifest).join(' ')).toMatch(/not collected/);
  });
  it('is indeterminate with no actors and no spike', () => {
    expect(classify(base)).toBe('indeterminate');
  });
  it('is organic for a spike with no actor blocks', () => {
    expect(classify({ ...base, spikes: [{ ...base.spikes[0], isSpike: true, ratio: 9 }] })).toBe('organic');
  });
  it('always states that response bodies are never logged', () => {
    expect(limitsFor(base, manifest).join(' ')).toMatch(/bodies are never logged/);
  });
});
