import { DEFAULT_BRANDING } from '@cclabsnz/sf-core';
import type { AuditContext } from '@cclabsnz/sf-core';
import { buildAuditResult } from '../../../src/findings/scoring.js';
import type { Finding } from '../../../src/findings/Finding.js';
import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';
import { MarkdownRenderer } from '../../../src/renderers/MarkdownRenderer.js';
import { ClientReportRenderer } from '../../../src/renderers/ClientReportRenderer.js';

const ctx = {
  soql: {}, tooling: {}, rest: {}, cache: {},
  orgInfo: { id: '00Dxx0000000000EAA', name: 'Acme', type: 'Developer Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com' },
} as unknown as AuditContext;

const f = (checkId: string, over: Partial<Finding>): Finding => ({
  id: `${checkId}-x`, checkId, category: 'c', riskLevel: 'LOW', title: 't', detail: 'd', remediation: 'r', ...over,
});

// One passing check and one blind one whose id carries markup: 50% coverage, grade capped.
const result = buildAuditResult(ctx, [f('ok-check', { passed: true }), f('<b>blind</b>', { inconclusive: true, notAssessed: true })], {});

describe('coverage display', () => {
  it('HTML shows the coverage line, flags the cap and escapes the check ids', () => {
    const html = new HtmlRenderer().render(result);
    expect(html).toContain('Evidence coverage 50% (1 of 2 checks); grade capped at B');
    expect(html).toContain('&lt;b&gt;blind&lt;/b&gt;');
    expect(html).not.toContain('<b>blind</b>');
  });

  it('Markdown shows the coverage line and lists what was not assessed', () => {
    const md = new MarkdownRenderer().render(result);
    expect(md).toContain('**Evidence coverage 50% (1 of 2 checks); grade capped at B');
    expect(md).toContain('Not assessed:');
  });

  it('the executive summary says the unassessed areas are not clean', () => {
    const html = new ClientReportRenderer({ branding: DEFAULT_BRANDING, topN: 5, frameworks: ['OWASP'] }).render(result);
    expect(html).toContain('Evidence coverage 50%');
    expect(html).toContain('unassessed, not clean');
  });
});
