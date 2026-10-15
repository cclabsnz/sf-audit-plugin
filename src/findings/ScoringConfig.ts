import { z } from 'zod';
import type { RiskLevel } from '@cclabsnz/sf-core';

const nonNegativeInt = z.number().int().nonnegative();

// Every object is strict: an unknown or misspelled key ("gradeTresholds", "minscore") is an error,
// not a silently ignored override. Keep this in step with schemas/scoring-config.schema.json —
// test/unit/findings/ScoringConfig.test.ts checks the two agree.
const gradeConditionsSchema = z.strictObject({
  minScore: nonNegativeInt.max(100).optional(),
  maxCritical: nonNegativeInt.optional(),
  maxHigh: nonNegativeInt.optional(),
  maxMedium: nonNegativeInt.optional(),
});

export const scoringConfigSchema = z.strictObject({
  /** Editor hint pointing at schemas/scoring-config.schema.json; ignored. */
  $schema: z.string().optional(),
  /** Free-text note, as in config/scoring.sample.json; ignored. */
  _comment: z.string().optional(),
  /** When provided, ALL five risk levels (CRITICAL, HIGH, MEDIUM, LOW, INFO) must be present.
   * The entire object is replaced atomically during merge, not key-by-key. */
  riskScores: z
    .strictObject({
      CRITICAL: nonNegativeInt,
      HIGH: nonNegativeInt,
      MEDIUM: nonNegativeInt,
      LOW: nonNegativeInt,
      INFO: nonNegativeInt,
    })
    .optional(),
  checkWeights: z.record(z.string(), nonNegativeInt).optional(),
  gradeThresholds: z
    .strictObject({
      A: gradeConditionsSchema.optional(),
      B: gradeConditionsSchema.optional(),
      C: gradeConditionsSchema.optional(),
      D: gradeConditionsSchema.optional(),
      F: gradeConditionsSchema.optional(),
    })
    .optional(),
});

export type ScoringConfigInput = z.infer<typeof scoringConfigSchema>;

export interface GradeConditions {
  minScore?: number;
  maxCritical?: number;
  maxHigh?: number;
  maxMedium?: number;
}

export interface ScoringConfig {
  riskScores: Record<RiskLevel, number>;
  checkWeights: Record<string, number>;
  gradeThresholds: Record<'A' | 'B' | 'C' | 'D' | 'F', GradeConditions>;
}

export const DEFAULT_SCORING_CONFIG: ScoringConfig = {
  riskScores: { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 },
  checkWeights: {},
  gradeThresholds: {
    A: { minScore: 85, maxHigh: 0 },
    B: { minScore: 70, maxHigh: 1 },
    C: { minScore: 55, maxHigh: 3 },
    D: { minScore: 40, maxCritical: 0 },
    F: {},
  },
};
