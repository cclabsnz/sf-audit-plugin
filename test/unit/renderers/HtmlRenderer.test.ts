import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';
import type { AuditResult } from '../../../src/findings/AuditResult.js';
import type { AttackChain } from '../../../src/chains/AttackChain.js';
import { EMPTY_METRICS } from '@cclabsnz/sf-core';

const SAMPLE_CHAIN: AttackChain = {
  id: 'unauth-bulk-exfil',
  title: 'Unauthenticated bulk exfiltration',
  severity: 'CRITICAL',
  confidence: 'named',
  narrative: 'Guest foothold + guest-executable Apex without sharing leads to bulk read.',
  remediation: 'Lock down guest access and add with sharing.',
  steps: [
    { findingId: 'guest-user-read-access', checkId: 'guest-user-access', capability: 'unauth-foothold', title: 'Guest read', severity: 'HIGH' },
    { findingId: 'guest-executable-apex-unprotected', checkId: 'guest-executable-apex', capability: 'code-exec', title: 'Unprotected Apex', severity: 'CRITICAL' },
  ],
};

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    generatedAt: new Date('2026-01-01'),
    orgId: 'org123',
    orgName: 'Test Org',
    orgType: 'Enterprise',
    isSandbox: false,
    instance: 'NA1',
    instanceUrl: 'https://test.salesforce.com',
    findings: [],
    metrics: EMPTY_METRICS,
    healthScore: 85,
    grade: 'B',
    attackChains: [],
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

  it('renders an Attack Paths section with the chain title', () => {
    const html = new HtmlRenderer().render({ ...makeResult(), attackChains: [SAMPLE_CHAIN] });
    expect(html).toContain('Attack Paths');
    expect(html).toContain('Unauthenticated bulk exfiltration');
  });

  it('is fully self-contained — no external asset fetches', () => {
    const html = renderer.render(makeResult());
    // The report claims to be offline-first and carries sensitive org findings; it must not
    // fetch fonts, styles or script from a third party when a client opens it.
    expect(html).not.toMatch(/<script[^>]+\ssrc=/i);
    expect(html).not.toMatch(/<link[^>]+\srel=["']?(stylesheet|preconnect)/i);
    expect(html).not.toContain('fonts.googleapis.com');
    expect(html).not.toContain('fonts.gstatic.com');
  });

  it('embeds the report webfonts as data URIs', () => {
    const html = renderer.render(makeResult());
    expect(html).toContain("@font-face{font-family: 'Fira Sans'");
    expect(html).toContain('src:url(data:font/woff2;base64,');
  });
});
