// test/unit/renderers/DiffJsonRenderer.test.ts
import { DiffJsonRenderer } from '../../../src/renderers/DiffJsonRenderer.js';
import { computeDiff } from '../../../src/history/DiffEngine.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-23T15:10:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

const BASELINE = makeResult({ healthScore: 64, grade: 'D' });
const CURRENT  = makeResult({ healthScore: 81, grade: 'B', generatedAt: new Date('2026-04-09T11:22:00Z') });

describe('DiffJsonRenderer', () => {
  const renderer = new DiffJsonRenderer();

  it('has format="json" and fileExtension=".json"', () => {
    expect(renderer.format).toBe('json');
    expect(renderer.fileExtension).toBe('.json');
  });

  it('produces valid JSON', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(() => JSON.parse(renderer.render(diff))).not.toThrow();
  });

  it('includes baseline, current, scoreDelta, gradeDelta, findingChanges, metricDeltas', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    const parsed = JSON.parse(renderer.render(diff));
    expect(parsed).toHaveProperty('baseline');
    expect(parsed).toHaveProperty('current');
    expect(parsed).toHaveProperty('scoreDelta', 17);
    expect(parsed).toHaveProperty('gradeDelta', 'D → B');
    expect(parsed).toHaveProperty('findingChanges');
    expect(parsed).toHaveProperty('metricDeltas');
  });
});
