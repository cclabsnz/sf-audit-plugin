import { MarkdownRenderer } from '../../../src/renderers/MarkdownRenderer.js';
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

describe('MarkdownRenderer', () => {
  const renderer = new MarkdownRenderer();

  it('has format="md" and fileExtension=".md"', () => {
    expect(renderer.format).toBe('md');
    expect(renderer.fileExtension).toBe('.md');
  });

  it('includes org name in output', () => {
    const output = renderer.render(makeResult());
    expect(output).toContain('Test Org');
  });

  it('includes healthScore and grade', () => {
    const output = renderer.render(makeResult({ healthScore: 75, grade: 'B' }));
    expect(output).toContain('75');
    expect(output).toContain('B');
  });

  it('renders finding titles and risk levels', () => {
    const result = makeResult({
      findings: [
        { id: 'f1', category: 'Auth', riskLevel: 'CRITICAL', title: 'MFA not enforced', detail: 'd', remediation: 'r' },
      ],
    });
    const output = renderer.render(result);
    expect(output).toContain('CRITICAL');
    expect(output).toContain('MFA not enforced');
  });

  it('shows "No findings" message when findings array is empty', () => {
    const output = renderer.render(makeResult());
    expect(output).toContain('No findings');
  });
});
