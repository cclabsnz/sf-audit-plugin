import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scoringConfigSchema, DEFAULT_SCORING_CONFIG } from '../../../src/findings/ScoringConfig.js';
import { loadScoringConfig } from '../../../src/findings/loadScoringConfig.js';
import { CHECKS } from '../../../src/checks/registry.js';

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

  it('rejects partial riskScores (all five levels required when present)', () => {
    expect(() =>
      scoringConfigSchema.parse({ riskScores: { CRITICAL: 10 } }),
    ).toThrow();
  });

  it('DEFAULT_SCORING_CONFIG has correct grade thresholds', () => {
    expect(DEFAULT_SCORING_CONFIG.gradeThresholds.A.minScore).toBe(85);
    expect(DEFAULT_SCORING_CONFIG.gradeThresholds.B.minScore).toBe(70);
    expect(DEFAULT_SCORING_CONFIG.gradeThresholds.C.minScore).toBe(55);
    expect(DEFAULT_SCORING_CONFIG.gradeThresholds.D.minScore).toBe(40);
    expect(DEFAULT_SCORING_CONFIG.gradeThresholds.F).toEqual({});
  });

  it('DEFAULT_SCORING_CONFIG has empty checkWeights', () => {
    expect(DEFAULT_SCORING_CONFIG.checkWeights).toEqual({});
  });

  describe('loadScoringConfig actionable schema errors', () => {
    it('fails fast with exact schema path when scoring config is malformed', () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-scoring-test-'));
      const badConfig = path.join(tmpDir, 'bad-scoring.json');
      try {
        fs.writeFileSync(
          badConfig,
          JSON.stringify({
            riskScores: {
              CRITICAL: 'NOT_A_NUMBER',
              HIGH: 7,
              MEDIUM: 4,
              LOW: 1,
              INFO: 0,
            },
          }),
        );

        expect(() => loadScoringConfig(badConfig, new Set(), () => {})).toThrow(
          /Invalid scoring config in '.*bad-scoring\.json':\n\s+- riskScores\.CRITICAL:/,
        );
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });
  });
});

// ---------------------------------------------------------------------------------------------
// schemas/scoring-config.schema.json is what editors validate against; the zod schema in
// ScoringConfig.ts is what the loader enforces. Nothing generates one from the other, so these
// tests hold them together. The JSON Schema is checked with a deliberately small validator that
// throws on any keyword it does not implement — adding one to the schema fails here first, rather
// than being silently ignored. (No ajv: it is not a declared dependency.)
// ---------------------------------------------------------------------------------------------

type JsonSchema = Record<string, unknown>;
const ROOT = process.cwd();
const JSON_SCHEMA = JSON.parse(fs.readFileSync(path.join(ROOT, 'schemas/scoring-config.schema.json'), 'utf8')) as JsonSchema;
const SAMPLE = JSON.parse(fs.readFileSync(path.join(ROOT, 'config/scoring.sample.json'), 'utf8')) as {
  checkWeights: Record<string, unknown>;
};
const IGNORED_KEYWORDS = new Set(['$schema', '$id', 'title', 'description', '$comment', '$defs']);

function jsonSchemaErrors(schema: JsonSchema, value: unknown, at = 'root'): string[] {
  if (typeof schema.$ref === 'string') {
    const m = /^#\/\$defs\/(.+)$/.exec(schema.$ref);
    if (!m) throw new Error(`unsupported $ref ${schema.$ref}`);
    return jsonSchemaErrors((JSON_SCHEMA.$defs as Record<string, JsonSchema>)[m[1]], value, at);
  }
  const errors: string[] = [];
  for (const kw of Object.keys(schema)) {
    if (IGNORED_KEYWORDS.has(kw)) continue;
    switch (kw) {
      case 'type': {
        const ok =
          schema.type === 'object' ? typeof value === 'object' && value !== null && !Array.isArray(value)
          : schema.type === 'integer' ? Number.isInteger(value)
          : schema.type === 'string' ? typeof value === 'string'
          : (() => { throw new Error(`unsupported type ${String(schema.type)}`); })();
        if (!ok) return [`${at}: expected ${String(schema.type)}`];
        break;
      }
      case 'minimum':
        if (typeof value === 'number' && value < (schema.minimum as number)) errors.push(`${at}: below minimum`);
        break;
      case 'maximum':
        if (typeof value === 'number' && value > (schema.maximum as number)) errors.push(`${at}: above maximum`);
        break;
      case 'required':
        for (const k of schema.required as string[]) {
          if (!(k in (value as object))) errors.push(`${at}.${k}: required`);
        }
        break;
      case 'properties':
      case 'additionalProperties':
        break; // handled together below
      default:
        throw new Error(`jsonSchemaErrors does not implement keyword '${kw}' — extend it`);
    }
  }
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    const props = (schema.properties ?? {}) as Record<string, JsonSchema>;
    for (const [k, v] of Object.entries(value)) {
      if (k in props) errors.push(...jsonSchemaErrors(props[k], v, `${at}.${k}`));
      else if (schema.additionalProperties === false) errors.push(`${at}.${k}: not allowed`);
      else if (typeof schema.additionalProperties === 'object') {
        errors.push(...jsonSchemaErrors(schema.additionalProperties as JsonSchema, v, `${at}.${k}`));
      }
    }
  }
  return errors;
}

const fullRisk = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 };

/** Inputs both schemas must agree on — accepted by both, or rejected by both. */
const AGREEMENT_CASES: Array<[string, unknown]> = [
  ['empty', {}],
  ['$schema and _comment', { $schema: './schemas/scoring-config.schema.json', _comment: 'x' }],
  ['full riskScores', { riskScores: fullRisk }],
  ['partial riskScores', { riskScores: { CRITICAL: 10 } }],
  ['extra riskScores level', { riskScores: { ...fullRisk, SEVERE: 12 } }],
  ['negative riskScore', { riskScores: { ...fullRisk, LOW: -1 } }],
  ['fractional riskScore', { riskScores: { ...fullRisk, LOW: 0.5 } }],
  ['string riskScore', { riskScores: { ...fullRisk, LOW: '1' } }],
  ['checkWeight', { checkWeights: { 'apex-sharing': 3 } }],
  ['zero checkWeight', { checkWeights: { 'apex-sharing': 0 } }],
  ['negative checkWeight', { checkWeights: { 'apex-sharing': -2 } }],
  ['string checkWeight', { checkWeights: { _comment: 'note' } }],
  ['grade threshold', { gradeThresholds: { A: { minScore: 90 } } }],
  ['minScore 100', { gradeThresholds: { A: { minScore: 100 } } }],
  ['minScore over 100', { gradeThresholds: { A: { minScore: 101 } } }],
  ['negative maxHigh', { gradeThresholds: { B: { maxHigh: -1 } } }],
  ['unknown grade', { gradeThresholds: { E: {} } }],
  ['lowercase grade', { gradeThresholds: { a: { minScore: 90 } } }],
  ['misspelled condition', { gradeThresholds: { A: { minscore: 90 } } }],
  ['misspelled section', { gradeTresholds: { A: { minScore: 90 } } }],
  ['not an object', []],
];

describe('scoring config: JSON Schema and zod schema agree', () => {
  it.each(AGREEMENT_CASES)('%s', (_name, input) => {
    const jsonOk = jsonSchemaErrors(JSON_SCHEMA, input).length === 0;
    const zodOk = scoringConfigSchema.safeParse(input).success;
    expect({ jsonOk, zodOk }).toEqual({ jsonOk: zodOk, zodOk });
  });

  it('rejects misspelled keys instead of silently ignoring them', () => {
    expect(scoringConfigSchema.safeParse({ gradeTresholds: {} }).success).toBe(false);
    expect(scoringConfigSchema.safeParse({ gradeThresholds: { A: { minscore: 90 } } }).success).toBe(false);
  });
});

describe('config/scoring.sample.json', () => {
  const knownIds = new Set(CHECKS.map((c) => c.id));
  const usable = (): unknown => {
    const copy = structuredClone(SAMPLE);
    delete copy.checkWeights._comment; // the documented "to use" step
    return copy;
  };

  it('lists exactly the registered check ids in checkWeights', () => {
    const keys = Object.keys(SAMPLE.checkWeights).filter((k) => k !== '_comment').sort();
    expect(keys).toEqual([...knownIds].sort());
  });

  it('is valid against the JSON Schema once the checkWeights _comment is removed', () => {
    expect(jsonSchemaErrors(JSON_SCHEMA, usable())).toEqual([]);
  });

  it('loads cleanly through loadScoringConfig once the checkWeights _comment is removed', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-scoring-sample-'));
    const file = path.join(tmpDir, 'scoring.json');
    try {
      fs.writeFileSync(file, JSON.stringify(usable()));
      const warnings: string[] = [];
      const cfg = loadScoringConfig(file, knownIds, (m) => warnings.push(m));
      expect(warnings).toEqual([]);
      expect(Object.keys(cfg.checkWeights)).toHaveLength(knownIds.size);
      expect(cfg.gradeThresholds).toEqual(DEFAULT_SCORING_CONFIG.gradeThresholds);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('as shipped is rejected, pointing at checkWeights._comment', () => {
    expect(() => loadScoringConfig(path.join(ROOT, 'config/scoring.sample.json'), knownIds, () => {})).toThrow(
      /checkWeights\._comment/,
    );
  });
});

describe('loadScoringConfig grade threshold ordering', () => {
  const load = (cfg: unknown): (() => unknown) => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-scoring-order-'));
    const file = path.join(tmpDir, 'scoring.json');
    fs.writeFileSync(file, JSON.stringify(cfg));
    return () => {
      try {
        return loadScoringConfig(file, new Set(), () => {});
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    };
  };

  it('rejects a grade whose minScore is below the next grade down', () => {
    expect(load({ gradeThresholds: { A: { minScore: 60 } } })).toThrow(
      /gradeThresholds\.A\.minScore \(60\) is below gradeThresholds\.B\.minScore \(70\)/,
    );
  });

  it('rejects a grade that tolerates more HIGH findings than the next grade down', () => {
    expect(load({ gradeThresholds: { B: { maxHigh: 5 } } })).toThrow(/gradeThresholds\.B\.maxHigh \(5\) is above gradeThresholds\.C\.maxHigh \(3\)/);
  });

  it('accepts a consistently stricter set of thresholds', () => {
    expect(load({ gradeThresholds: { A: { minScore: 90 }, B: { minScore: 75 }, C: { minScore: 60 } } })).not.toThrow();
  });
});
