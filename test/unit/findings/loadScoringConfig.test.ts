import { expect, describe, it, beforeEach, jest } from '@jest/globals';
import { loadScoringConfig } from '../../../src/findings/loadScoringConfig.js';
import { DEFAULT_SCORING_CONFIG } from '../../../src/findings/ScoringConfig.js';

const KNOWN_CHECK_IDS = new Set([
  'apex-sharing', 'api-limits', 'audit-trail', 'code-security', 'connected-apps',
  'custom-settings', 'field-level-security', 'flows-without-sharing', 'guest-user-access',
  'hardcoded-credentials', 'health-check', 'inactive-users', 'ip-restrictions',
  'login-session', 'named-credentials', 'password-session-policy', 'permissions',
  'public-group-sharing', 'remote-sites', 'scheduled-apex', 'sharing-model', 'users-and-admins',
]);

describe('loadScoringConfig', () => {
  const warn = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns defaults when no path is provided', () => {
    const result = loadScoringConfig(undefined, KNOWN_CHECK_IDS, warn);
    expect(result).toEqual(DEFAULT_SCORING_CONFIG);
    expect(warn).not.toHaveBeenCalled();
  });

  it('deep-merges overrides onto defaults', () => {
    const mockRead = jest.fn(() => JSON.stringify({ riskScores: { CRITICAL: 15, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }));
    const result = loadScoringConfig('./custom.json', KNOWN_CHECK_IDS, warn, mockRead);
    expect(result.riskScores.CRITICAL).toBe(15);
    expect(result.riskScores.HIGH).toBe(7); // unchanged default
    expect(result.checkWeights).toEqual({}); // default preserved
  });

  it('merges checkWeights onto empty default', () => {
    const mockRead = jest.fn(() => JSON.stringify({ checkWeights: { 'apex-sharing': 12 } }));
    const result = loadScoringConfig('./custom.json', KNOWN_CHECK_IDS, warn, mockRead);
    expect(result.checkWeights['apex-sharing']).toBe(12);
  });

  it('warns on unknown check IDs but continues', () => {
    const mockRead = jest.fn(() => JSON.stringify({ checkWeights: { 'not-a-check': 5 } }));
    const result = loadScoringConfig('./custom.json', KNOWN_CHECK_IDS, warn, mockRead);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('not-a-check'));
    expect(result.checkWeights['not-a-check']).toBeUndefined(); // unknown keys are dropped
  });

  it('throws on invalid JSON', () => {
    const mockRead = jest.fn(() => 'not valid json');
    expect(() => loadScoringConfig('./bad.json', KNOWN_CHECK_IDS, warn, mockRead)).toThrow();
  });

  it('throws on schema validation failure', () => {
    const mockRead = jest.fn(() => JSON.stringify({ riskScores: { CRITICAL: -1, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }));
    expect(() => loadScoringConfig('./bad.json', KNOWN_CHECK_IDS, warn, mockRead)).toThrow();
  });
});
