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
          Status: 'Active',
        },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('org-wide-email-spoofing-ok');
    expect(r.findings[0].passed).toBe(true);
  });
});
