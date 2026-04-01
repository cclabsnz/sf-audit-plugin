import { scoringConfigSchema, DEFAULT_SCORING_CONFIG } from '../../../src/findings/ScoringConfig.js';

describe('scoringConfigSchema', () => {
  it('accepts a full valid config', () => {
    const input = {
      riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
      checkWeights: { 'apex-sharing': 5 },
      gradeThresholds: {
        A: { minScore: 85, maxHigh: 0 },
        B: { minScore: 70, maxHigh: 1 },
        C: { minScore: 55, maxHigh: 3 },
        D: { minScore: 40, maxCritical: 0 },
        F: {},
      },
    };
    expect(() => scoringConfigSchema.parse(input)).not.toThrow();
  });

  it('accepts an empty object (all defaults)', () => {
    expect(() => scoringConfigSchema.parse({})).not.toThrow();
  });

  it('rejects negative risk scores', () => {
    expect(() =>
      scoringConfigSchema.parse({ riskScores: { CRITICAL: -1, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }),
    ).toThrow();
  });

  it('rejects non-integer risk scores', () => {
    expect(() =>
      scoringConfigSchema.parse({ riskScores: { CRITICAL: 1.5, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 } }),
    ).toThrow();
  });

  it('rejects negative check weights', () => {
    expect(() =>
      scoringConfigSchema.parse({ checkWeights: { 'apex-sharing': -1 } }),
    ).toThrow();
  });

  it('DEFAULT_SCORING_CONFIG has all five risk levels', () => {
    expect(DEFAULT_SCORING_CONFIG.riskScores.CRITICAL).toBe(10);
    expect(DEFAULT_SCORING_CONFIG.riskScores.HIGH).toBe(7);
    expect(DEFAULT_SCORING_CONFIG.riskScores.MEDIUM).toBe(4);
    expect(DEFAULT_SCORING_CONFIG.riskScores.LOW).toBe(1);
    expect(DEFAULT_SCORING_CONFIG.riskScores.INFO).toBe(0);
  });
});
