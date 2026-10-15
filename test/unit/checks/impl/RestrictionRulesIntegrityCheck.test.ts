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
          Active: false,
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'restriction-rules-inactive');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('flags multiple active restriction rules on the same TargetEntity', async () => {
    const ctx = makeCtx({
      RestrictionRule: [
        {
          Id: '0RR2',
          MasterLabel: 'Contract Rule A',
          TargetEntity: 'Contract',
          Active: true,
        },
        {
          Id: '0RR3',
          MasterLabel: 'Contract Rule B',
          TargetEntity: 'Contract',
          Active: true,
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'restriction-rules-conflicting');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('passes when each target entity has exactly one active rule', async () => {
    const ctx = makeCtx({
      RestrictionRule: [
        {
          Id: '0RR4',
          MasterLabel: 'Task Rule',
          TargetEntity: 'Task',
          Active: true,
        },
        {
          Id: '0RR5',
          MasterLabel: 'Contract Rule',
          TargetEntity: 'Contract',
          Active: true,
        },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('restriction-rules-integrity-ok');
    expect(r.findings[0].passed).toBe(true);
  });
});
