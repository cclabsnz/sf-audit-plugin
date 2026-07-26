import { ClientReportRenderer } from '../../../src/renderers/ClientReportRenderer.js';
import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import type { AuditResult } from '../../../src/findings/AuditResult.js';

function makeResult(): AuditResult {
  return {
    generatedAt: new Date('2026-06-14T00:00:00Z'),
    orgId: '00Dxx', orgName: 'Acme', orgType: 'Production', isSandbox: false,
    instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com',
    healthScore: 62, grade: 'C',
    metrics: {} as never,
    findings: [
      { id: 'f1', checkId: 'internal-user-mfa', category: 'Authentication', riskLevel: 'CRITICAL',
        title: '3 admins without MFA', detail: 'd', remediation: 'Enforce MFA', complianceTags: ['OWASP-A07'] },
      { id: 'f2', checkId: 'sharing-model', category: 'Data', riskLevel: 'HIGH',
        title: 'Loose OWD', detail: 'd', remediation: 'Tighten OWD' },
    ],
    attackChains: [
      { id: 'c1', title: 'Account takeover', severity: 'CRITICAL', confidence: 'named',
        narrative: 'Stolen password to full org access.', remediation: 'Enforce MFA',
        steps: [{ findingId: 'f1', capability: 'INITIAL_ACCESS' as never, title: '3 admins without MFA', severity: 'CRITICAL' }] },
    ],
  };
}

describe('ClientReportRenderer', () => {
  const r = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5, frameworks: ['OWASP'] });

  it('renders the compliance matrix for selected frameworks', () => {
    const html = r.render(makeResult());
    expect(html).toContain('Compliance Coverage');
    expect(html).toContain('OWASP-A07');
    expect(html).toContain('OWASP Top 10:2021');
  });

  it('declares the executive format and html extension', () => {
    expect(r.format).toBe('executive');
    expect(r.fileExtension).toBe('.html');
    expect(r.filenamePrefix).toBe('SF_Audit_Executive');
  });

  it('renders a self-contained branded report with all sections', () => {
    const html = r.render(makeResult());
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('CloudCounsel Limited');
    expect(html).toContain('Executive Summary');
    expect(html).toContain('Executive Priorities');
    expect(html).toContain('Attack Scenarios');
    expect(html).toContain('Remediation Roadmap');
    expect(html).toContain('Grade');
    expect(html).toContain('Account takeover');
    expect(html).toContain('@font-face');
    expect(html).not.toContain('http://');
  });

  it('shows the per-check impact narrative for a priority', () => {
    const html = r.render(makeResult());
    expect(html).toContain('no second factor');
  });

  it('escapes finding titles', () => {
    const res = makeResult();
    res.findings[0].title = '<script>x</script>';
    expect(r.render(res)).not.toContain('<script>x</script>');
  });
});
