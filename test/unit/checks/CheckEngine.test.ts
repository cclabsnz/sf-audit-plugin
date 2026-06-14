import { jest } from '@jest/globals';
import { CheckEngine } from '../../../src/checks/CheckEngine.js';
import type { SecurityCheck, CheckResult } from '../../../src/checks/SecurityCheck.js';
import type { AuditContext } from '../../../src/context/AuditContext.js';
import { CHECK_CONTROL_MAP } from '../../../src/compliance/mapping.js';
import { getComplianceTags } from '../../../src/compliance/resolve.js';

function makeCtx(): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'orgId', name: 'Test Org', type: 'Developer Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://test.salesforce.com' },
    cache: {},
  };
}

function makeCheck(id: string, result: Partial<CheckResult> = {}): SecurityCheck {
  const fn: any = jest.fn();
  fn.mockResolvedValue({ findings: [], ...result });
  return {
    id,
    name: `Check ${id}`,
    category: 'Test',
    description: `Test check ${id}`,
    run: fn,
  };
}

describe('CheckEngine', () => {
  describe('constructor — validateCacheOrdering()', () => {
    it('accepts empty check list', () => {
      expect(() => new CheckEngine([], makeCtx())).not.toThrow();
    });

    it('accepts checks where dependencies are satisfied by preceding checks', () => {
      const producer: SecurityCheck = {
        ...makeCheck('producer'),
        populatesCache: ['apexBodies'],
      };
      const consumer: SecurityCheck = {
        ...makeCheck('consumer'),
        dependsOnCache: ['apexBodies'],
      };
      expect(() => new CheckEngine([producer, consumer], makeCtx())).not.toThrow();
    });

    it('throws when a check depends on a cache key no preceding check populates', () => {
      const consumer: SecurityCheck = {
        ...makeCheck('consumer'),
        dependsOnCache: ['apexBodies'],
      };
      expect(() => new CheckEngine([consumer], makeCtx())).toThrow(
        "Check 'Check consumer' depends on cache key 'apexBodies' but no preceding check declares it in populatesCache."
      );
    });

    it('throws when the dependency is declared in a later check (wrong order)', () => {
      const consumer: SecurityCheck = {
        ...makeCheck('consumer'),
        dependsOnCache: ['apexBodies'],
      };
      const producer: SecurityCheck = {
        ...makeCheck('producer'),
        populatesCache: ['apexBodies'],
      };
      expect(() => new CheckEngine([consumer, producer], makeCtx())).toThrow(/apexBodies/);
    });
  });

  describe('run()', () => {
    it('returns an AuditResult with empty findings for empty check list', async () => {
      const engine = new CheckEngine([], makeCtx());
      const result = await engine.run();
      expect(result.findings).toHaveLength(0);
      expect(result.healthScore).toBe(100);
      expect(result.grade).toBe('A');
    });

    it('collects findings from all checks', async () => {
      const check1 = makeCheck('c1', {
        findings: [
          { id: 'f1', category: 'Auth', riskLevel: 'HIGH', title: 'Issue', detail: 'd', remediation: 'r' },
        ],
      });
      const check2 = makeCheck('c2', {
        findings: [
          { id: 'f2', category: 'Apex', riskLevel: 'LOW', title: 'Minor', detail: 'd', remediation: 'r' },
        ],
      });

      const engine = new CheckEngine([check1, check2], makeCtx());
      const result = await engine.run();

      expect(result.findings).toHaveLength(2);
      expect(result.findings[0].checkId).toBe('c1');
    });

    it('catches per-check errors and adds an INFO error finding instead of aborting', async () => {
      const failFn: any = jest.fn();
      failFn.mockRejectedValue(new Error('SOQL error'));
      const failingCheck: SecurityCheck = {
        ...makeCheck('bad'),
        run: failFn,
      };
      const goodCheck = makeCheck('good', {
        findings: [
          { id: 'f1', category: 'Auth', riskLevel: 'LOW', title: 'T', detail: 'd', remediation: 'r' },
        ],
      });

      const engine = new CheckEngine([failingCheck, goodCheck], makeCtx());
      const result = await engine.run();

      expect(result.findings).toHaveLength(2);
      const errorFinding = result.findings.find((f) => f.id === 'bad-error');
      expect(errorFinding).toBeDefined();
      expect(errorFinding!.riskLevel).toBe('INFO');
      expect(errorFinding!.detail).toContain('SOQL error');
      expect(errorFinding!.checkId).toBe('bad');
    });

    it('merges metrics from all checks', async () => {
      const check1 = makeCheck('c1', { metrics: { totalActiveUsers: 10 } });
      const check2 = makeCheck('c2', { metrics: { apexClassCount: 50 } });

      const engine = new CheckEngine([check1, check2], makeCtx());
      const result = await engine.run();

      expect(result.metrics.totalActiveUsers).toBe(10);
      expect(result.metrics.apexClassCount).toBe(50);
    });

    it('enriches findings with compliance tags from ComplianceMapping', async () => {
      const check = makeCheck('users-and-admins', {
        findings: [{ id: 'f1', category: 'Access', riskLevel: 'HIGH' as const, title: 'Test', detail: 'x', remediation: 'y' }],
      });
      const engine = new CheckEngine([check], makeCtx());
      const result = await engine.run();
      expect(result.findings[0].complianceTags).toContain('OWASP-A01');
      expect(result.findings[0].complianceTags).toContain('SOC2-CC6.1');
    });

    it('sets empty complianceTags array for unknown check IDs', async () => {
      const check = makeCheck('unknown-check-xyz', {
        findings: [{ id: 'f1', category: 'Test', riskLevel: 'INFO' as const, title: 'T', detail: 'd', remediation: 'r' }],
      });
      const engine = new CheckEngine([check], makeCtx());
      const result = await engine.run();
      expect(result.findings[0].complianceTags).toEqual([]);
    });

    it('marks findings inconclusive when check throws a permission error', async () => {
      const check = makeCheck('c-perm');
      const permError = new Error('INSUFFICIENT_ACCESS_RIGHTS: cannot query') as Error & { errorCode?: string };
      permError.errorCode = 'INSUFFICIENT_ACCESS_RIGHTS';
      (check.run as any).mockRejectedValue(permError);
      const engine = new CheckEngine([check], makeCtx());
      const result = await engine.run();
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].inconclusive).toBe(true);
      expect(result.findings[0].riskLevel).toBe('INFO');
    });

    it('does NOT mark findings inconclusive for non-permission errors', async () => {
      const check = makeCheck('c-err');
      (check.run as any).mockRejectedValue(new Error('Network timeout'));
      const engine = new CheckEngine([check], makeCtx());
      const result = await engine.run();
      expect(result.findings[0].inconclusive).toBeUndefined();
      expect(result.findings[0].riskLevel).toBe('INFO');
    });
  });

  describe('ComplianceMapping', () => {
    it('CHECK_CONTROL_MAP covers every registered check ID', async () => {
      const { CHECKS } = await import('../../../src/checks/registry.js');
      for (const check of CHECKS) {
        expect(CHECK_CONTROL_MAP).toHaveProperty(check.id);
      }
    });

    it('getComplianceTags returns tags for a known check ID', () => {
      expect(getComplianceTags('users-and-admins')).toContain('OWASP-A01');
      expect(getComplianceTags('users-and-admins')).toContain('SOC2-CC6.1');
    });

    it('getComplianceTags returns empty array for unknown check ID', () => {
      expect(getComplianceTags('nonexistent-check')).toEqual([]);
    });
  });
});
