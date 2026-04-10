// test/unit/renderers/DiffHtmlRenderer.test.ts
import { DiffHtmlRenderer } from '../../../src/renderers/DiffHtmlRenderer.js';
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

const BASELINE = makeResult({
  healthScore: 64,
  grade: 'D',
  findings: [
    { id: 'f-resolved', checkId: 'c1', category: 'Auth', riskLevel: 'HIGH', title: 'Old finding', detail: 'detail', remediation: 'fix' },
    { id: 'f-new-base', checkId: 'c2', category: 'Auth', riskLevel: 'LOW',  title: 'Stays',       detail: 'detail', remediation: 'fix' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 5 },
});

const CURRENT = makeResult({
  healthScore: 81,
  grade: 'B',
  generatedAt: new Date('2026-04-09T11:22:00Z'),
  findings: [
    { id: 'f-new-cur',  checkId: 'c3', category: 'Auth', riskLevel: 'CRITICAL', title: 'New one',  detail: 'detail', remediation: 'fix' },
    { id: 'f-new-base', checkId: 'c2', category: 'Auth', riskLevel: 'LOW',       title: 'Stays',   detail: 'detail', remediation: 'fix' },
  ],
  metrics: { ...EMPTY_METRICS, modifyAllDataUsersCount: 3 },
});

describe('DiffHtmlRenderer', () => {
  const renderer = new DiffHtmlRenderer();

  it('has format="html" and fileExtension=".html"', () => {
    expect(renderer.format).toBe('html');
    expect(renderer.fileExtension).toBe('.html');
  });

  it('produces a valid HTML document', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    const html = renderer.render(diff);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
  });

  it('includes org name in the output', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('Test Org');
  });

  it('includes score delta', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('+17');
  });

  it('includes grade delta', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('D → B');
  });

  it('shows new finding title', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('New one');
  });

  it('shows resolved finding title', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('Old finding');
  });

  it('includes metric delta label', () => {
    const diff = computeDiff(BASELINE, CURRENT);
    expect(renderer.render(diff)).toContain('Modify All Data Users');
  });
});
