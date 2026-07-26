import { describe, it, expect } from '@jest/globals';
import { computeEvidenceTier } from '../../../src/probe/evidenceTier.js';
import type {
  EventMonitoringCoverage,
  FieldHistoryCoverage,
  BehavioralTablesCoverage,
} from '../../../src/probe/types.js';

const em = (level: EventMonitoringCoverage['level']): EventMonitoringCoverage => ({
  level,
  access: level === 'none' ? 'not-enabled' : 'ok',
  intervals: [],
  eventTypes: [],
  eventTypeCount: 0,
  note: '',
});

const fh = (opts: Partial<FieldHistoryCoverage>): FieldHistoryCoverage => ({
  objects: [],
  trackedObjectCount: 0,
  fieldAuditTrail: false,
  note: '',
  ...opts,
});

const bt = (tables: BehavioralTablesCoverage['tables']): BehavioralTablesCoverage => ({ tables });

describe('computeEvidenceTier', () => {
  it('A: full EM + Field Audit Trail', () => {
    expect(computeEvidenceTier(em('full'), fh({ fieldAuditTrail: true }), bt([]), true)).toBe('A');
  });

  it('B: behavioural table with data', () => {
    const tier = computeEvidenceTier(
      em('free-tier'),
      fh({}),
      bt([{ name: 'CaseHistory', access: 'ok', rowCount12mo: 20 }]),
      true,
    );
    expect(tier).toBe('B');
  });

  it('C: describable but no behavioural rows readable', () => {
    const tier = computeEvidenceTier(
      em('none'),
      fh({}),
      bt([{ name: 'CaseHistory', access: 'not-present', rowCount12mo: null }]),
      true,
    );
    expect(tier).toBe('C');
  });

  it('D: nothing readable at all', () => {
    const tier = computeEvidenceTier(
      em('none'),
      fh({}),
      bt([{ name: 'CaseHistory', access: 'not-present', rowCount12mo: null }]),
      false,
    );
    expect(tier).toBe('D');
  });
});
