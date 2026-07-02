import { jest } from '@jest/globals';
import { LoginAccessPolicyCheck } from '../../../../src/checks/impl/LoginAccessPolicyCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(opts: { groups?: unknown[]; groupsThrow?: boolean; loginAsAnyUser?: boolean; withMetadata?: boolean }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async () => {
    if (opts.groupsThrow) throw new Error('no access');
    return opts.groups ?? [];
  });
  const metadata =
    opts.withMetadata || opts.loginAsAnyUser !== undefined
      ? { read: (async () => ({ enableAdminLoginAsAnyUser: opts.loginAsAnyUser ?? false })) as any }
      : undefined;
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    metadata,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('LoginAccessPolicyCheck', () => {
  const check = new LoginAccessPolicyCheck();

  it('is inconclusive when DelegateGroup is inaccessible', async () => {
    const r = await check.run(makeCtx({ groupsThrow: true }));
    expect(r.findings[0].id).toBe('login-access-policy-inconclusive');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('flags delegated administration groups and always emits the login-as advisory', async () => {
    const r = await check.run(makeCtx({ groups: [{ Id: '1', DeveloperName: 'RegionalAdmins' }] }));
    expect(r.findings.find((f) => f.id === 'login-access-policy-delegated-admins')?.riskLevel).toBe('MEDIUM');
    expect(r.findings.some((f) => f.id === 'login-access-policy-login-as-advisory')).toBe(true);
  });

  it('emits the manual advisory when no Metadata client is available', async () => {
    const r = await check.run(makeCtx({ groups: [] }));
    expect(r.findings.some((f) => f.id === 'login-access-policy-ok' && f.passed)).toBe(true);
    expect(r.findings.some((f) => f.id === 'login-access-policy-login-as-advisory')).toBe(true);
  });

  it('detects login-as-any-user ENABLED via metadata as HIGH', async () => {
    const r = await check.run(makeCtx({ groups: [], loginAsAnyUser: true }));
    const f = r.findings.find((x) => x.id === 'login-access-policy-login-as-enabled');
    expect(f?.riskLevel).toBe('HIGH');
    expect(r.findings.some((x) => x.id === 'login-access-policy-login-as-advisory')).toBe(false);
  });

  it('confirms login-as-any-user DISABLED via metadata as a pass', async () => {
    const r = await check.run(makeCtx({ groups: [], loginAsAnyUser: false }));
    expect(r.findings.some((f) => f.id === 'login-access-policy-login-as-disabled' && f.passed)).toBe(true);
  });
});
