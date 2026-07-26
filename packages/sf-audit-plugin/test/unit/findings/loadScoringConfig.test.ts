import { jest, describe, it, expect, beforeEach } from '@jest/globals';

const mockReadFileSync = jest.fn();

jest.unstable_mockModule('node:fs', () => ({
  readFileSync: mockReadFileSync,
}));

const { loadScoringConfig } = await import('../../../src/findings/loadScoringConfig.js');
const { DEFAULT_SCORING_CONFIG } = await import('../../../src/findings/ScoringConfig.js');

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
    mockReadFileSync.mockReturnValue(JSON.stringify({ riskScores: { CRITICAL: 15, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }));
    const result = loadScoringConfig('./custom.json', KNOWN_CHECK_IDS, warn);
    expect(result.riskScores.CRITICAL).toBe(15);
    expect(result.riskScores.HIGH).toBe(7);
    expect(result.checkWeights).toEqual({});
  });

  it('merges checkWeights onto empty default', () => {
    mockReadFileSync.mockReturnValue(JSON.stringify({ checkWeights: { 'apex-sharing': 12 } }));
    const result = loadScoringConfig('./custom.json', KNOWN_CHECK_IDS, warn);
    expect(result.checkWeights['apex-sharing']).toBe(12);
  });

  it('warns on unknown check IDs but continues', () => {
    mockReadFileSync.mockReturnValue(JSON.stringify({ checkWeights: { 'not-a-check': 5 } }));
    const result = loadScoringConfig('./custom.json', KNOWN_CHECK_IDS, warn);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('not-a-check'));
    expect(result.checkWeights['not-a-check']).toBeUndefined();
  });

  it('throws on invalid JSON', () => {
    mockReadFileSync.mockReturnValue('not valid json');
    expect(() => loadScoringConfig('./bad.json', KNOWN_CHECK_IDS, warn)).toThrow();
  });

  it('throws on schema validation failure', () => {
    mockReadFileSync.mockReturnValue(JSON.stringify({ riskScores: { CRITICAL: -1, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }));
    expect(() => loadScoringConfig('./bad.json', KNOWN_CHECK_IDS, warn)).toThrow();
  });

  it('throws with a descriptive message when the file does not exist', () => {
    mockReadFileSync.mockImplementation(() => {
      throw Object.assign(new Error('no such file or directory'), { code: 'ENOENT' });
    });
    expect(() => loadScoringConfig('./missing.json', KNOWN_CHECK_IDS, warn)).toThrow(
      /Cannot read scoring config file.*missing\.json/,
    );
  });
});
