import { jest } from '@jest/globals';
import { AnonymousApexAuditCheck } from '../../../../src/checks/impl/AnonymousApexAuditCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(trail: unknown[] | Error): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation(() =>
        trail instanceof Error ? Promise.reject(trail) : Promise.resolve(trail),
      ),
      query: jest.fn(),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const exec = (userId: string, profile: string | null = 'Standard User', daysAgo = 3) => ({
  CreatedDate: new Date(Date.now() - daysAgo * 86_400_000).toISOString(),
  CreatedBy: {
    Id: userId, Username: `${userId}@x.com`,
    Profile: profile === null ? null : { Name: profile },
  },
  Section: 'Developer Console', Action: 'executeCode', Display: 'Executed anonymous Apex',
});

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('AnonymousApexAuditCheck', () => {
  const check = new AnonymousApexAuditCheck();

  it('is inconclusive when SetupAuditTrail cannot be queried', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS')));
    expect(r.findings[0].id).toBe('anonymous-apex-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('passes when no anonymous execution is recorded', async () => {
    const r = await check.run(makeCtx([]));
    expect(r.findings[0].id).toBe('anonymous-apex-none');
    expect(r.findings[0].passed).toBe(true);
  });

  it('scopes the query to 90 days and the developer-tool sections', async () => {
    const ctx = makeCtx([]);
    await check.run(ctx);
    const q = (ctx.soql.queryAll as any).mock.calls[0][0] as string;
    expect(q).toMatch(/LAST_N_DAYS:90/);
    expect(q).toContain('Developer Console');
    expect(q).toMatch(/executeCode/);
  });

  // A non-admin running anonymous Apex in production is the control gap; an admin doing it is
  // a change-management concern. Different severities, reported separately.
  it('rates non-admin execution HIGH and admin execution MEDIUM', async () => {
    const r = await check.run(makeCtx([
      exec('dev', 'Standard User'),
      exec('boss', 'System Administrator'),
    ]));
    expect(find(r, 'anonymous-apex-executed')!.riskLevel).toBe('HIGH');
    expect(find(r, 'anonymous-apex-admin-only')!.riskLevel).toBe('MEDIUM');
  });

  it('aggregates repeated executions per user and keeps the latest date', async () => {
    const r = await check.run(makeCtx([
      exec('dev', 'Standard User', 30),
      exec('dev', 'Standard User', 1),
      exec('dev', 'Standard User', 60),
    ]));
    const f = find(r, 'anonymous-apex-executed')!;
    expect(f.title).toContain('1 non-admin user(s)');
    const note = f.affectedItems![0].note!;
    expect(note).toContain('3 execution(s)');
    // The most recent execution wins, not the first row seen.
    expect(note).toContain(new Date(Date.now() - 1 * 86_400_000).toISOString().split('T')[0]);
  });

  it('treats an unknown profile as non-admin, the safer default', async () => {
    const r = await check.run(makeCtx([exec('mystery', null)]));
    expect(find(r, 'anonymous-apex-executed')).toBeDefined();
    expect(find(r, 'anonymous-apex-executed')!.affectedItems![0].note).toContain('Unknown');
  });

  it('reports only the admin finding when every executor is an admin', async () => {
    const r = await check.run(makeCtx([exec('boss', 'System Administrator')]));
    expect(find(r, 'anonymous-apex-executed')).toBeUndefined();
    expect(find(r, 'anonymous-apex-admin-only')).toBeDefined();
  });
});
