import { jest } from '@jest/globals';
import { SoapLoginApiAuthCheck } from '../../../../src/checks/impl/SoapLoginApiAuthCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

type Rows = { records: unknown[] };
type Step = Rows | Error;

/**
 * The check issues up to three queries in a fixed order: LoginHistory aggregate,
 * PermissionSetAssignment, then User. Each test supplies the steps it expects to be
 * reached, and `calls` lets a test assert the later ones were never issued.
 */
function makeCtx(steps: Step[]): AuditContext & { calls: string[] } {
  const calls: string[] = [];
  let i = 0;
  const ctx = {
    soql: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        calls.push(q);
        const step = steps[i++];
        if (step === undefined) throw new Error(`unexpected query #${i}: ${q}`);
        return step instanceof Error ? Promise.reject(step) : Promise.resolve(step);
      }),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
    calls,
  } as any;
  return ctx;
}

const soapRow = (UserId: string, over = 1, ApiType = 'SOAP Partner', Application = 'DataLoader') =>
  ({ UserId, Application, ApiType, logins: over });

const holder = (Id: string, Username: string, ownedByProfile = false, profile = 'Integration') => ({
  Assignee: { Id, Username, Profile: { Name: profile } },
  PermissionSet: { Name: 'Legacy SOAP Access', IsOwnedByProfile: ownedByProfile },
});

const user = (Id: string, Username: string, profile = 'Integration') =>
  ({ Id, Username, Profile: { Name: profile } });

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('SoapLoginApiAuthCheck', () => {
  const check = new SoapLoginApiAuthCheck();

  // spec case 1
  it('passes when no SOAP logins appear in the window', async () => {
    const ctx = makeCtx([
      { records: [{ UserId: '005a', Application: 'Browser', ApiType: null, logins: 9 }] },
      { records: [] },
    ]);
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('soap-login-api-auth-ok-no-soap');
    expect(r.findings[0].passed).toBe(true);
    expect(ctx.calls).toHaveLength(2); // never resolves usernames
  });

  // spec case 2
  it('passes when every SOAP caller already holds the permission', async () => {
    const r = await check.run(makeCtx([
      { records: [soapRow('005a')] },
      { records: [holder('005a', 'svc@acme.com')] },
      { records: [user('005a', 'svc@acme.com')] },
    ]));
    expect(find(r, 'soap-login-api-auth-ok-covered')?.passed).toBe(true);
    expect(find(r, 'soap-login-api-auth-missing')).toBeUndefined();
  });

  // spec case 3
  it('flags only the SOAP caller that lacks the permission', async () => {
    const r = await check.run(makeCtx([
      { records: [soapRow('005a'), soapRow('005b')] },
      { records: [holder('005a', 'covered@acme.com')] },
      { records: [user('005a', 'covered@acme.com'), user('005b', 'exposed@acme.com')] },
    ]));
    const f = find(r, 'soap-login-api-auth-missing');
    expect(f?.riskLevel).toBe('HIGH');
    expect(f!.affectedItems).toHaveLength(1);
    expect(f!.affectedItems![0].label).toBe('exposed@acme.com');
  });

  // spec case 4
  it('reports a permission holder who never used SOAP as LOW', async () => {
    const r = await check.run(makeCtx([
      { records: [soapRow('005a')] },
      { records: [holder('005a', 'svc@acme.com'), holder('005z', 'idle@acme.com')] },
      { records: [user('005a', 'svc@acme.com')] },
    ]));
    const f = find(r, 'soap-login-api-auth-unnecessary');
    expect(f?.riskLevel).toBe('LOW');
    expect(f!.affectedItems!.map((i) => i.label)).toEqual(['idle@acme.com']);
    expect(f!.affectedItems![0].note).toContain('Legacy SOAP Access');
  });

  // spec case 5
  it('escalates to MEDIUM when the unnecessary grant comes from a profile', async () => {
    const r = await check.run(makeCtx([
      { records: [soapRow('005a')] },
      { records: [holder('005a', 'svc@acme.com'), holder('005z', 'idle@acme.com', true, 'Sales User')] },
      { records: [user('005a', 'svc@acme.com')] },
    ]));
    const f = find(r, 'soap-login-api-auth-unnecessary');
    expect(f?.riskLevel).toBe('MEDIUM');
    expect(f!.affectedItems![0].note).toContain('Profile (Sales User)');
  });

  // spec case 6
  it('is inconclusive and stops when LoginHistory is unreadable', async () => {
    const ctx = makeCtx([new Error('INSUFFICIENT_ACCESS')]);
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('soap-login-api-auth-inconclusive-history');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(ctx.calls).toHaveLength(1); // never asks about the permission
  });

  // spec case 7
  it('is inconclusive with a distinct id when the permission field is absent', async () => {
    const ctx = makeCtx([
      { records: [soapRow('005a')] },
      new Error('No such column PermissionsUseAnyApiAuth'),
    ]);
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('soap-login-api-auth-inconclusive-field');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(ctx.calls).toHaveLength(2);
  });

  // spec case 8 — the regression the spec calls out as most likely
  it('sums logins and lists a user once when they appear under several client identities', async () => {
    const r = await check.run(makeCtx([
      { records: [
        soapRow('005b', 3, 'SOAP Partner', 'DataLoader'),
        soapRow('005b', 4, 'SOAP Enterprise', 'Custom Client'),
      ] },
      { records: [] },
      { records: [user('005b', 'exposed@acme.com')] },
    ]));
    const f = find(r, 'soap-login-api-auth-missing');
    expect(f!.affectedItems).toHaveLength(1);
    expect(f!.affectedItems![0].note).toContain('7 SOAP login(s)');
  });

  it('matches SOAP on Application when ApiType is absent', async () => {
    const r = await check.run(makeCtx([
      { records: [{ UserId: '005b', Application: 'SOAP Client', ApiType: null, logins: 2 }] },
      { records: [] },
      { records: [user('005b', 'exposed@acme.com')] },
    ]));
    expect(find(r, 'soap-login-api-auth-missing')).toBeDefined();
  });

  it('ignores an inactive SOAP caller that the User query does not return', async () => {
    const r = await check.run(makeCtx([
      { records: [soapRow('005dead')] },
      { records: [] },
      { records: [] },
    ]));
    expect(find(r, 'soap-login-api-auth-missing')).toBeUndefined();
    expect(find(r, 'soap-login-api-auth-ok-covered')?.passed).toBe(true);
  });
});
