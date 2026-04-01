import * as fs from 'node:fs';
import { scoringConfigSchema, DEFAULT_SCORING_CONFIG } from './ScoringConfig.js';
import type { ScoringConfig } from './ScoringConfig.js';

export function loadScoringConfig(
  filePath: string | undefined,
  knownCheckIds: Set<string>,
  warn: (msg: string) => void,
): ScoringConfig {
  if (!filePath) return DEFAULT_SCORING_CONFIG;

  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    throw new Error(`Cannot read scoring config file '${filePath}': ${err instanceof Error ? err.message : String(err)}`);
  }
  const parsed: unknown = JSON.parse(raw);
  const validated = scoringConfigSchema.parse(parsed); // throws ZodError on failure

  // Warn on unknown check IDs and drop them
  const safeCheckWeights: Record<string, number> = {};
  for (const [id, weight] of Object.entries(validated.checkWeights ?? {})) {
    if (!knownCheckIds.has(id)) {
      warn(`Unknown check ID in --scoring-config checkWeights: '${id}'. Run 'sf audit list' to see valid IDs. Skipping.`);
    } else {
      safeCheckWeights[id] = weight;
    }
  }

  return {
    riskScores: validated.riskScores ?? DEFAULT_SCORING_CONFIG.riskScores,
    checkWeights: safeCheckWeights,
    gradeThresholds: {
      A: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.A, ...(validated.gradeThresholds?.A ?? {}) },
      B: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.B, ...(validated.gradeThresholds?.B ?? {}) },
      C: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.C, ...(validated.gradeThresholds?.C ?? {}) },
      D: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.D, ...(validated.gradeThresholds?.D ?? {}) },
      F: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.F, ...(validated.gradeThresholds?.F ?? {}) },
    },
  };
}
