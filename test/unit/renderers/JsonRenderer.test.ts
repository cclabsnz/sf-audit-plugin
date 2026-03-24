import { JsonRenderer } from '../../../src/renderers/JsonRenderer.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-03-24T00:00:00Z'),
    orgId: '00D000000000001',
    orgName: 'Test Org',
    orgType: 'Developer Edition',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 100,
    grade: 'A',
    ...overrides,
  };
}

describe('JsonRenderer', () => {
  const renderer = new JsonRenderer();

  it('has format="json" and fileExtension=".json"', () => {
    expect(renderer.format).toBe('json');
    expect(renderer.fileExtension).toBe('.json');
  });

  it('renders a valid JSON string', () => {
    const output = renderer.render(makeResult());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('preserves all AuditResult fields in output', () => {
    const result = makeResult({
      findings: [
        { id: 'f1', category: 'Auth', riskLevel: 'HIGH', title: 'T', detail: 'd', remediation: 'r' },
      ],
      healthScore: 70,
      grade: 'C',
    });
    const parsed = JSON.parse(renderer.render(result));
    expect(parsed.healthScore).toBe(70);
    expect(parsed.grade).toBe('C');
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].riskLevel).toBe('HIGH');
  });
});
