import * as fs from 'node:fs';
import { z } from 'zod';
import { scoringConfigSchema, DEFAULT_SCORING_CONFIG } from './ScoringConfig.js';
import type { ScoringConfig, ScoringConfigInput } from './ScoringConfig.js';

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
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in scoring config '${filePath}': ${err instanceof Error ? err.message : String(err)}`);
  }

  let validated: ScoringConfigInput;
  try {
    validated = scoringConfigSchema.parse(parsed);
  } catch (err) {
    if (err instanceof z.ZodError) {
      const details = err.issues.map((i) => `  - ${i.path.join('.') || 'root'}: ${i.message}`).join('\n');
      throw new Error(`Invalid scoring config in '${filePath}':\n${details}`);
    }
    throw err;
  }

  // Warn on unknown check IDs and drop them
  const safeCheckWeights: Record<string, number> = {};
  const rawWeights: Record<string, number> = validated.checkWeights ?? {};
  for (const [id, weight] of Object.entries(rawWeights)) {
    if (!knownCheckIds.has(id)) {
      warn(`Unknown check ID in --scoring-config checkWeights: '${id}'. Run 'sf audit list' to see valid IDs. Skipping.`);
    } else {
      safeCheckWeights[id] = weight;
    }
  }

  const gradeThresholds: ScoringConfig['gradeThresholds'] = {
    A: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.A, ...validated.gradeThresholds?.A },
    B: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.B, ...validated.gradeThresholds?.B },
    C: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.C, ...validated.gradeThresholds?.C },
    D: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.D, ...validated.gradeThresholds?.D },
    F: { ...DEFAULT_SCORING_CONFIG.gradeThresholds.F, ...validated.gradeThresholds?.F },
  };
  const orderErrors = thresholdOrderErrors(gradeThresholds);
  if (orderErrors.length > 0) {
    throw new Error(
      `Invalid scoring config in '${filePath}' (grade thresholds after merging with defaults):\n${orderErrors.map((e) => `  - ${e}`).join('\n')}`,
    );
  }

  return {
    riskScores: validated.riskScores ?? DEFAULT_SCORING_CONFIG.riskScores,
    checkWeights: safeCheckWeights,
    gradeThresholds,
  };
}

const GRADE_ORDER = ['A', 'B', 'C', 'D'] as const;

/**
 * Grades are tried A first, then B, C, D, so each grade must be at least as strict as the next.
 * A lower bar on A than on B would make B unreachable, which is never what the author meant.
 * The JSON Schema cannot express this cross-field rule, so it lives here, applied to the merged
 * result (a one-grade override can contradict a default on its neighbour).
 */
function thresholdOrderErrors(t: ScoringConfig['gradeThresholds']): string[] {
  const errors: string[] = [];
  for (let i = 0; i < GRADE_ORDER.length - 1; i++) {
    const hi = GRADE_ORDER[i];
    const lo = GRADE_ORDER[i + 1];
    const a = t[hi];
    const b = t[lo];
    if (a.minScore !== undefined && b.minScore !== undefined && a.minScore < b.minScore) {
      errors.push(`gradeThresholds.${hi}.minScore (${a.minScore}) is below gradeThresholds.${lo}.minScore (${b.minScore})`);
    }
    for (const key of ['maxCritical', 'maxHigh', 'maxMedium'] as const) {
      const av = a[key];
      const bv = b[key];
      if (av !== undefined && bv !== undefined && av > bv) {
        errors.push(`gradeThresholds.${hi}.${key} (${av}) is above gradeThresholds.${lo}.${key} (${bv})`);
      }
    }
  }
  return errors;
}
