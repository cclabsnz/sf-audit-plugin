// test/unit/renderers/HistoryRenderer.test.ts
import { HistoryRenderer } from '../../../src/renderers/HistoryRenderer.js';
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
    instanceUrl: 'https://test.salesforce.com',
    findings: [],
    metrics: { ...EMPTY_METRICS },
    healthScore: 64,
    grade: 'D',
    ...overrides,
  };
}

const R1 = makeResult({ generatedAt: new Date('2026-03-23T15:10:00Z'), healthScore: 64, grade: 'D', findings: [{ id: 'f1', checkId: 'c1', category: 'Auth', riskLevel: 'CRITICAL', title: 'T', detail: 'd', remediation: 'r' }] });
const R2 = makeResult({ generatedAt: new Date('2026-04-09T11:22:00Z'), healthScore: 81, grade: 'B', findings: [] });

describe('HistoryRenderer', () => {
  const renderer = new HistoryRenderer();

  describe('renderTable', () => {
    it('includes org name in header', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('Test Org');
    });

    it('shows score for each run', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('64');
      expect(table).toContain('81');
    });

    it('shows delta score from second run onward', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('+17');
    });

    it('shows — for first run delta', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('—');
    });

    it('includes trend summary line', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('Trend');
    });

    it('shows finding counts per severity', () => {
      const table = renderer.renderTable([R1, R2]);
      expect(table).toContain('1'); // R1 has 1 CRITICAL
    });
  });

  describe('renderHtml', () => {
    it('produces a valid HTML document with Chart.js', () => {
      const html = renderer.renderHtml([R1, R2]);
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('chart.js');
    });

    it('includes org name', () => {
      expect(renderer.renderHtml([R1, R2])).toContain('Test Org');
    });

    it('embeds health scores as Chart.js data', () => {
      const html = renderer.renderHtml([R1, R2]);
      expect(html).toContain('64');
      expect(html).toContain('81');
    });
  });
});
