import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import { EMPTY_METRICS } from '../../../src/context/OrgMetrics.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-01-01'),
    orgId: 'org123',
    orgName: 'Test Org',
    orgType: 'Enterprise',
    isSandbox: false,
    instance: 'NA1',
    findings: [],
    metrics: EMPTY_METRICS,
    healthScore: 85,
    grade: 'B',
    ...overrides,
  };
}

const renderer = new HtmlRenderer();

describe('HtmlRenderer', () => {
  it('renders compliance tags as chips on finding cards', () => {
    const result = makeResult({
      findings: [{
        id: 'f1', checkId: 'users-and-admins', category: 'Access', riskLevel: 'HIGH',
        title: 'Test Finding', detail: 'detail', remediation: 'fix it',
        complianceTags: ['OWASP-A01', 'SOC2-CC6.1'],
      }],
    });
    const html = renderer.render(result);
    expect(html).toContain('OWASP-A01');
    expect(html).toContain('SOC2-CC6.1');
    expect(html).toContain('compliance-tag');
  });

  it('renders inconclusive findings with a distinct style', () => {
    const result = makeResult({
      findings: [{
        id: 'f2', checkId: 'some-check', category: 'Access', riskLevel: 'INFO',
        title: 'Insufficient Permissions', detail: 'could not query', remediation: 'grant access',
        inconclusive: true,
      }],
    });
    const html = renderer.render(result);
    expect(html).toContain('is-inconclusive');
    expect(html).toContain('INCONCLUSIVE');
  });

  it('renders the offline-first footer', () => {
    const html = renderer.render(makeResult());
    expect(html).toContain('no data');
    expect(html).toContain('offline');
  });
});
