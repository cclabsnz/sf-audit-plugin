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

  it('renders affectedItems as a markdown table with label, url, and note columns', () => {
    const result = makeResult({
      findings: [{
        id: 'f1', category: 'Auth', riskLevel: 'HIGH', title: 'Inactive users', detail: 'd', remediation: 'r',
        affectedItems: [
          { label: 'user@example.com', url: 'https://org.salesforce.com/005abc', note: 'Last login: never' },
          { label: 'other@example.com', url: 'https://org.salesforce.com/005def', note: 'Last login: 2024-01-01' },
        ],
      }],
    });
    const output = renderer.render(result);
    expect(output).toContain('| Item | Setup Link | Notes |');
    expect(output).toContain('user@example.com');
    expect(output).toContain('[Open ↗](https://org.salesforce.com/005abc)');
    expect(output).toContain('Last login: never');
  });

  it('omits Setup Link column when no items have urls', () => {
    const result = makeResult({
      findings: [{
        id: 'f1', category: 'Code', riskLevel: 'MEDIUM', title: 'Apex classes', detail: 'd', remediation: 'r',
        affectedItems: [{ label: 'MyClass', note: 'Add with sharing' }],
      }],
    });
    const output = renderer.render(result);
    expect(output).toContain('| Item | Notes |');
    expect(output).not.toContain('Setup Link');
    expect(output).toContain('MyClass');
  });

  it('omits Notes column when no items have notes', () => {
    const result = makeResult({
      findings: [{
        id: 'f1', category: 'Auth', riskLevel: 'LOW', title: 'PS check', detail: 'd', remediation: 'r',
        affectedItems: [{ label: 'My PS', url: 'https://org.salesforce.com/0PS123' }],
      }],
    });
    const output = renderer.render(result);
    expect(output).toContain('| Item | Setup Link |');
    expect(output).not.toContain('Notes');
    expect(output).toContain('[Open ↗](https://org.salesforce.com/0PS123)');
  });
});
