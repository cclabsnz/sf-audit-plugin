import { describe, it, expect } from '@jest/globals';
import { LOG_TYPES, REQUIRED_LOG_TYPES, id15, DEFAULTS } from '../../../src/incident/model.js';

describe('incident model', () => {
  it('lists the collected log types and the required subset', () => {
    expect(LOG_TYPES).toContain('AuraRequest');
    expect(LOG_TYPES).toContain('Sites');
    expect(REQUIRED_LOG_TYPES).toEqual(['AuraRequest', 'Sites']);
  });
  it('normalises ids to 15 characters', () => {
    expect(id15('005xx000000gstAAAA')).toBe('005xx000000gstA');
    expect(id15('005xx000000gstA')).toBe('005xx000000gstA');
    expect(id15(undefined)).toBeUndefined();
    expect(id15('  ')).toBeUndefined();
  });
  it('pins the agreed thresholds', () => {
    expect(DEFAULTS).toEqual({ spikeRatio: 5, emptyBandBytes: 64, auditWindowDays: 4, auditPageCap: 10000, outlierFloor: 100, outlierMultiple: 3, sharedEgressUsers: 8 });
  });
});
