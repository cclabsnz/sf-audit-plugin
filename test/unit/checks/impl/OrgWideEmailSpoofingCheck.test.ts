import { jest } from '@jest/globals';
import { OrgWideEmailSpoofingCheck } from '../../../../src/checks/impl/OrgWideEmailSpoofingCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(soqlResponses: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(soqlResponses)) {
          if (q.includes(key)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
        }
        return Promise.resolve([]);
      }),
    } as any,
    tooling: {} as any,
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

describe('OrgWideEmailSpoofingCheck', () => {
  const check = new OrgWideEmailSpoofingCheck();

  it('flags OrgWideEmailAddress open to all profiles and missing DKIM keys', async () => {
    const ctx = makeCtx({
      OrgWideEmailAddress: [
        {
          Id: '0D21',
          Address: 'billing@company.com',
          DisplayName: 'Billing Dept',
          IsAllowAllProfiles: true,
        },
      ],
      DkimKey: [],
    });
    const r = await check.run(ctx);
    const owaFinding = r.findings.find((x) => x.id === 'org-wide-email-spoofing-all-profiles');
    expect(owaFinding).toBeDefined();
    expect(owaFinding?.riskLevel).toBe('MEDIUM');

    const dkimFinding = r.findings.find((x) => x.id === 'org-wide-email-spoofing-no-dkim');
    expect(dkimFinding).toBeDefined();
    expect(dkimFinding?.riskLevel).toBe('MEDIUM');
  });

  it('passes when addresses are scoped to specific profiles and DKIM is active', async () => {
    const ctx = makeCtx({
      OrgWideEmailAddress: [
        {
          Id: '0D22',
          Address: 'support@company.com',
          DisplayName: 'Support Team',
          IsAllowAllProfiles: false,
        },
      ],
      DkimKey: [
        {
          Id: '0Dk1',
          Domain: 'company.com',
          IsActive: true,
        },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('org-wide-email-spoofing-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('is inconclusive, never passed, when DkimKey cannot be read', async () => {
    const ctx = makeCtx({
      OrgWideEmailAddress: [{ Id: '0D23', Address: 'a@company.com', DisplayName: 'A', IsAllowAllProfiles: false }],
      DkimKey: new Error('INSUFFICIENT_ACCESS: DkimKey'),
    });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.passed)).toBe(false);
    expect(r.findings.map((f) => f.id)).toEqual(['org-wide-email-spoofing-dkim-inaccessible']);
  });

  it('does not report both inconclusive and passed when OrgWideEmailAddress cannot be read', async () => {
    const ctx = makeCtx({
      OrgWideEmailAddress: new Error('INSUFFICIENT_ACCESS: OrgWideEmailAddress'),
      DkimKey: [{ Id: '0Dk2', Domain: 'company.com', IsActive: true }],
    });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.passed)).toBe(false);
    expect(r.findings.map((f) => f.id)).toEqual(['org-wide-email-spoofing-inaccessible']);
  });

  it('treats a key that is not active as no DKIM', async () => {
    const ctx = makeCtx({
      OrgWideEmailAddress: [],
      DkimKey: [{ Id: '0Dk3', Domain: 'company.com', IsActive: false }],
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['org-wide-email-spoofing-no-dkim']);
  });
});
