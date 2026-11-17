import { jest } from '@jest/globals';
import { RestrictionRulesIntegrityCheck } from '../../../../src/checks/impl/RestrictionRulesIntegrityCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(toolingData: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(toolingData)) {
          if (q.includes(key)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
        }
        return Promise.resolve([]);
      }),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: '00D000000000001',
      name: 'Test Org',
      type: 'Developer Edition',
      isSandbox: false,
      instance: 'NA1',
      instanceUrl: 'https://test.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

describe('RestrictionRulesIntegrityCheck', () => {
  const check = new RestrictionRulesIntegrityCheck();

  it('passes when no restriction rules are configured', async () => {
    const ctx = makeCtx({ RestrictionRule: [] });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('restriction-rules-integrity-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags inactive restriction rules', async () => {
    const ctx = makeCtx({
      RestrictionRule: [
        {
          Id: '0RR1',
          MasterLabel: 'Restrict Sensitive Tasks',
          TargetEntity: 'Task',
          IsActive: false,
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'restriction-rules-inactive');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('flags active rules on one object with identical user criteria, at MEDIUM', async () => {
    const ctx = makeCtx({
      RestrictionRule: [
        { Id: '0RR2', MasterLabel: 'Contract Rule A', TargetEntity: 'Contract', IsActive: true, UserCriteria: '$User.UserType = \'Standard\'' },
        { Id: '0RR3', MasterLabel: 'Contract Rule B', TargetEntity: 'Contract', IsActive: true, UserCriteria: "$User.UserType='Standard'" },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'restriction-rules-conflicting');
    expect(f?.riskLevel).toBe('MEDIUM');
    expect(f?.affectedItems?.[0].label).toContain('Contract');
  });

  it('does not merge criteria that differ inside a quoted literal or by case', async () => {
    const ctx = makeCtx({
      RestrictionRule: [
        { Id: '0RR8', MasterLabel: 'A', TargetEntity: 'Contract', IsActive: true, UserCriteria: "$User.Title = 'Sales Rep'" },
        { Id: '0RR9', MasterLabel: 'B', TargetEntity: 'Contract', IsActive: true, UserCriteria: "$User.Title = 'SalesRep'" },
        { Id: '0RRa', MasterLabel: 'C', TargetEntity: 'Case', IsActive: true, UserCriteria: "$User.ProfileId = '00e000000000aBc'" },
        { Id: '0RRb', MasterLabel: 'D', TargetEntity: 'Case', IsActive: true, UserCriteria: "$User.ProfileId = '00e000000000abc'" },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['restriction-rules-integrity-ok']);
  });

  it('ignores duplicated scoping rules, which set default filters rather than restrict access', async () => {
    const ctx = makeCtx({
      RestrictionRule: [
        { Id: '0RRc', MasterLabel: 'S1', TargetEntity: 'Contract', IsActive: true, EnforcementType: 'Scoping', UserCriteria: "$User.UserType = 'Standard'" },
        { Id: '0RRd', MasterLabel: 'S2', TargetEntity: 'Contract', IsActive: true, EnforcementType: 'Scoping', UserCriteria: "$User.UserType = 'Standard'" },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['restriction-rules-integrity-ok']);
  });

  it('passes two active rules on one object scoped to different users', async () => {
    const ctx = makeCtx({
      RestrictionRule: [
        { Id: '0RR6', MasterLabel: 'Partners', TargetEntity: 'Contract', IsActive: true, UserCriteria: "$User.UserType = 'PowerPartner'" },
        { Id: '0RR7', MasterLabel: 'Contractors', TargetEntity: 'Contract', IsActive: true, UserCriteria: "$User.ProfileId = '00e000000000001'" },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['restriction-rules-integrity-ok']);
  });

  it('selects UserCriteria so it can compare rules', async () => {
    const ctx = makeCtx({ RestrictionRule: [] });
    await check.run(ctx);
    expect((ctx.tooling.query as any).mock.calls[0][0]).toContain('UserCriteria');
  });

  it('passes when each target entity has exactly one active rule', async () => {
    const ctx = makeCtx({
      RestrictionRule: [
        {
          Id: '0RR4',
          MasterLabel: 'Task Rule',
          TargetEntity: 'Task',
          IsActive: true,
        },
        {
          Id: '0RR5',
          MasterLabel: 'Contract Rule',
          TargetEntity: 'Contract',
          IsActive: true,
        },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('restriction-rules-integrity-ok');
    expect(r.findings[0].passed).toBe(true);
  });
});
