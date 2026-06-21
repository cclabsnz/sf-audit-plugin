import { jest } from '@jest/globals';
import { EmailSecurityCheck } from '../../../../src/checks/impl/EmailSecurityCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

// queryAll is dispatched by the SOQL text; map each FROM object to its canned rows.
function makeCtx(byObject: Record<string, unknown[] | Error>): AuditContext {
  const route = (soql: string): unknown[] => {
    const m = /FROM\s+(\w+)/i.exec(soql);
    const obj = m ? m[1] : '';
    const val = byObject[obj];
    if (val instanceof Error) throw val;
    if (val === undefined) throw Object.assign(new Error('not accessible'), { errorCode: 'ENTITY_IS_INACCESSIBLE' });
    return val;
  };
  return {
    soql: { query: jest.fn(), queryAll: (jest.fn() as any).mockImplementation(async (s: string) => route(s)) } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('EmailSecurityCheck', () => {
  const check = new EmailSecurityCheck();

  it('flags org-wide addresses available to all profiles as MEDIUM', async () => {
    const ctx = makeCtx({
      OrgWideEmailAddress: [{ Id: '1', Address: 'noreply@acme.com', DisplayName: 'Acme', IsAllowAllProfiles: true }],
      EmailServicesFunction: [],
      EmailServicesAddress: [],
    });
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'email-security-owa-all-profiles');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
  });

  it('flags unauthenticated active inbound email services as HIGH', async () => {
    const ctx = makeCtx({
      OrgWideEmailAddress: [],
      EmailServicesFunction: [{ Id: '1', FunctionName: 'CaseIntake', IsActive: true, IsAuthenticationRequired: false }],
      EmailServicesAddress: [],
    });
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'email-security-services-no-auth');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('flags email addresses with no authorized senders as MEDIUM', async () => {
    const ctx = makeCtx({
      OrgWideEmailAddress: [],
      EmailServicesFunction: [{ Id: '1', FunctionName: 'CaseIntake', IsActive: true, IsAuthenticationRequired: true }],
      EmailServicesAddress: [{ Id: 'a', LocalPart: 'cases', EmailDomainName: 'x.com', IsActive: true, AuthorizedSenders: '' }],
    });
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'email-security-addresses-open');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
  });

  it('passes when addresses are scoped and services authenticated', async () => {
    const ctx = makeCtx({
      OrgWideEmailAddress: [{ Id: '1', Address: 'noreply@acme.com', DisplayName: 'Acme', IsAllowAllProfiles: false }],
      EmailServicesFunction: [],
      EmailServicesAddress: [],
    });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'email-security-owa-ok' && f.passed)).toBe(true);
  });

  it('is inconclusive when a source is not accessible', async () => {
    const ctx = makeCtx({
      // OrgWideEmailAddress omitted -> throws -> inconclusive
      EmailServicesFunction: [],
      EmailServicesAddress: [],
    });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.inconclusive)).toBe(true);
  });
});
