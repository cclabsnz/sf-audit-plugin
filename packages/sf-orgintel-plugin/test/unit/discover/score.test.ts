import { describe, it, expect } from '@jest/globals';
import { scoreAnchors, type RawCandidate } from '../../../src/discover/score.js';
import { DEFAULT_WEIGHTS } from '../../../src/discover/scoringConfig.js';
import type { AnchorSignals } from '../../../src/discover/types.js';

function signals(p: Partial<AnchorSignals>): AnchorSignals {
  return {
    automation: { flows: 0, triggers: 0, approvals: 0, workflowRules: 0, total: 0 },
    statusField: null,
    totalRecords: null,
    created90d: null,
    inboundReferences: 0,
    activityAttach: null,
    activityApproximate: false,
    historyTracking: false,
    ...p,
  };
}

const cands: RawCandidate[] = [
  {
    object: 'Case',
    label: 'Case',
    custom: false,
    signals: signals({
      automation: { flows: 5, triggers: 3, approvals: 2, workflowRules: 2, total: 12 },
      statusField: { field: 'Status', label: 'Status', values: ['New', 'Working', 'Closed'], matchedByName: true },
      totalRecords: 50000,
      created90d: 4000,
      inboundReferences: 6,
      activityAttach: 100,
      historyTracking: true,
    }),
  },
  {
    object: 'Contact',
    label: 'Contact',
    custom: false,
    signals: signals({ totalRecords: 100000, created90d: 100, inboundReferences: 2 }),
  },
  {
    object: 'Claim__c',
    label: 'Claim',
    custom: true,
    signals: signals({
      automation: { flows: 1, triggers: 1, approvals: 0, workflowRules: 1, total: 3 },
      statusField: { field: 'Stage__c', label: 'Stage', values: ['A', 'B'], matchedByName: true },
      totalRecords: 500,
      created90d: 50,
      activityAttach: 10,
    }),
  },
];

describe('scoreAnchors', () => {
  const ranked = scoreAnchors(cands, DEFAULT_WEIGHTS);

  it('ranks the automation- and status-rich object first', () => {
    expect(ranked.map((r) => r.object)).toEqual(['Case', 'Claim__c', 'Contact']);
  });

  it('normalises and weights each signal transparently', () => {
    const caseRow = ranked[0];
    expect(caseRow.contributions.automation).toBeCloseTo(0.3, 5); // max automation -> full weight
    expect(caseRow.contributions.statusShaped).toBeCloseTo(0.15, 5);
    expect(caseRow.contributions.history).toBeCloseTo(0.1, 5);
    expect(caseRow.score).toBeCloseTo(0.97, 2);
  });

  it('builds human evidence lines', () => {
    const caseRow = ranked[0];
    expect(caseRow.evidence.some((l) => l.includes('12 automation'))).toBe(true);
    expect(caseRow.evidence.some((l) => l.includes('Status field Status [New → Working → Closed]'))).toBe(true);
    expect(caseRow.evidence.some((l) => l.includes('6 inbound lookup'))).toBe(true);
  });

  it('is deterministic', () => {
    expect(scoreAnchors(cands, DEFAULT_WEIGHTS)).toEqual(ranked);
  });
});
