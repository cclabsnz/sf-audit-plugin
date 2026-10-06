import { describe, it, expect } from '@jest/globals';
import { toolCreditHtml, toolCreditMarkdown, toolCreditUrl } from '../../../src/renderers/toolCredit.js';

describe('toolCredit', () => {
  it('tags the link with the report type only', () => {
    const url = new URL(toolCreditUrl('incident-report'));
    expect(url.protocol).toBe('https:');
    expect(Object.fromEntries(url.searchParams)).toEqual({ utm_source: 'sf-audit', utm_medium: 'report', utm_campaign: 'incident-report' });
  });

  it('renders the same credit in HTML and Markdown', () => {
    expect(toolCreditHtml('executive-report')).toContain(`<a href="${toolCreditUrl('executive-report')}">sf-audit</a>`);
    expect(toolCreditMarkdown('incident-report')).toContain(`[sf-audit](${toolCreditUrl('incident-report')})`);
  });
});
