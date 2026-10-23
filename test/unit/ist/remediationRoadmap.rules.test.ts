// IST visible rule tests for spec/remediation-roadmap.md (RULE-073..074, INT-013).
import { jest } from '@jest/globals';
import { buildRoadmap } from '../../../src/report/RemediationRoadmap.js';
import type { Finding } from '../../../src/findings/Finding.js';
import { LoginSessionCheck } from '../../../src/checks/impl/LoginSessionCheck.js';
import { HealthCheckCheck } from '../../../src/checks/impl/HealthCheckCheck.js';
import { UsersAndAdminsCheck } from '../../../src/checks/impl/UsersAndAdminsCheck.js';

const f = (riskLevel: Finding['riskLevel'], id: string, extra: Partial<Finding> = {}): Finding => ({
  id, checkId: 'inactive-users', category: 'T', riskLevel, title: id, detail: 'd', remediation: 'r', ...extra,
});

const all = (r: ReturnType<typeof buildRoadmap>) => [...r.quick, ...r.moderate, ...r.project].map((x) => x.id);

describe('RULE-073 the roadmap holds only open, assessed findings rated LOW or above (MN-057)', () => {
  it('leaves out INFO, not-assessed, passed, inconclusive and waived findings', () => {
    const r = buildRoadmap([
      f('LOW', 'keep-low'), f('HIGH', 'keep-high'),
      f('INFO', 'inventory'),
      f('INFO', 'inactive-users-error', { notAssessed: true }),
      f('MEDIUM', 'crashed', { notAssessed: true }),
      f('LOW', 'ok', { passed: true }),
      f('HIGH', 'blind', { inconclusive: true }),
      f('HIGH', 'accepted', { waived: true }),
    ]);
    expect(all(r).sort()).toEqual(['keep-high', 'keep-low']);
  });
});

const ORG = { id: 'o', name: 'n', type: 'EE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' };

describe('RULE-074 a healthy result is reported as passed, not as an open LOW finding', () => {
  it('failed-logins: 20 or fewer failures pass; more stay open', async () => {
    const run = (failed: number) => {
      const rows = [
        ...Array.from({ length: failed }, (_, i) => ({ Id: `f${i}`, Status: 'Invalid Password', UserId: 'u' })),
        ...Array.from({ length: 30 }, (_, i) => ({ Id: `s${i}`, Status: 'Success', UserId: 'u' })),
      ];
      const query = (jest.fn() as any).mockImplementation(() => Promise.resolve({ totalSize: rows.length, records: rows, done: true }));
      const queryAll = (jest.fn() as any).mockImplementation(() => Promise.resolve(rows));
      return new LoginSessionCheck().run({ soql: { query, queryAll } as any, tooling: {} as any, rest: {} as any, orgInfo: ORG, cache: {} as any } as any);
    };
    const pick = (r: { findings: Finding[] }) => r.findings.find((x) => x.id === 'failed-logins')!;
    expect(pick(await run(0)).passed).toBe(true);
    expect(pick(await run(20)).passed).toBe(true);
    expect(pick(await run(21)).passed).toBeFalsy();
  });

  it('health-check-score: 85 or more passes', async () => {
    const run = (score: number) =>
      new HealthCheckCheck().run({
        soql: { query: (jest.fn() as any).mockResolvedValue({ totalSize: 0, records: [], done: true }), queryAll: (jest.fn() as any).mockResolvedValue([]) } as any,
        tooling: { query: (jest.fn() as any).mockImplementation((q: string) => Promise.resolve(/SecurityHealthCheck\b(?!Risks)/.test(q) && !/Risks/.test(q) ? [{ Score: score }] : [])), getRecord: jest.fn() } as any,
        rest: {} as any, orgInfo: ORG, cache: {} as any,
      } as any);
    const pick = (r: { findings: Finding[] }) => r.findings.find((x) => x.id === 'health-check-score')!;
    expect(pick(await run(86)).passed).toBe(true);
    expect(pick(await run(84)).passed).toBeFalsy();
  });

  it('users-modify-all-data rated LOW and users-view-all-data with 5 or fewer holders pass, and keep their items', async () => {
    const row = (id: string) => ({
      Assignee: { Id: id, Username: `${id}@x.com`, Name: id, Profile: { Name: 'System Administrator' } },
      PermissionSet: { Name: 'PS', IsOwnedByProfile: false, PermissionsModifyAllData: true, PermissionsViewAllData: true,
        PermissionsManageUsers: false, PermissionsCustomizeApplication: false, PermissionsAuthorApex: false },
    });
    const rows = [row('a'), row('b')];
    const r = await new UsersAndAdminsCheck().run({
      soql: { queryAll: (jest.fn() as any).mockResolvedValue(rows), query: (jest.fn() as any).mockImplementation((s: string) => Promise.resolve({ totalSize: /PermissionSetAssignment/.test(s) ? rows.length : 50, records: [] })) } as any,
      tooling: {} as any, rest: {} as any, orgInfo: ORG, cache: {} as any,
    } as any);
    for (const id of ['users-modify-all-data', 'users-view-all-data']) {
      const x = r.findings.find((y) => y.id === id)!;
      expect(x.passed).toBe(true);
      expect(x.affectedItems).toHaveLength(2);
    }
  });
});

describe('RULE-074 passed population findings still feed attack chains', () => {
  it('a passed Modify/View All Data finding with holders still forms the insider chain', async () => {
    const { ChainEngine } = await import('../../../src/chains/ChainEngine.js');
    const item = [{ label: 'a@x.com' }];
    const findings: Finding[] = [
      { ...f('LOW', 'users-view-all-data', { passed: true, affectedItems: item }), checkId: 'users-and-admins' },
      { ...f('LOW', 'users-modify-all-data', { passed: true, affectedItems: item }), checkId: 'users-and-admins' },
      { ...f('HIGH', 'data-export-weekly-export'), checkId: 'data-export' },
      { ...f('HIGH', 'event-monitoring-disabled'), checkId: 'event-monitoring' },
    ];
    const ids = new ChainEngine().correlate(findings).map((c) => c.id);
    expect(ids).toContain('insider-bulk-exfil');
    const none = new ChainEngine().correlate(findings.map((x) => (x.id.startsWith('users-') ? { ...x, affectedItems: [] } : x))).map((c) => c.id);
    expect(none).not.toContain('insider-bulk-exfil');
  });
});
