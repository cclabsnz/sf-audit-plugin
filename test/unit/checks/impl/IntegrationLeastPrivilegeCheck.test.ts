import { jest } from '@jest/globals';
import { IntegrationLeastPrivilegeCheck } from '../../../../src/checks/impl/IntegrationLeastPrivilegeCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

interface Opts {
  users?: unknown[];
  usersThrow?: boolean;
  psa?: unknown[];
  psaThrow?: boolean;
}

function makeCtx(opts: Opts): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (soql: string) => {
    if (soql.includes('FROM PermissionSetAssignment')) {
      if (opts.psaThrow) throw new Error('no access');
      return opts.psa ?? [];
    }
    if (soql.includes('FROM User')) {
      if (opts.usersThrow) throw new Error('no access');
      return opts.users ?? [];
    }
    return [];
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

const SVC = [{
  Id: '005a', Username: 'svc.api@acme.com',
  Profile: { Name: 'Integration', UserLicense: { Name: 'Salesforce' } },
  LastLoginDate: '2026-08-25T00:00:00.000Z', CreatedDate: '2020-01-01T00:00:00.000Z',
}];

// Seven verified fields only — PermissionsViewSetup and PermissionsManageProfilesPermissionsets
// were dropped per controller ruling R12 (unverified field names, not in permCatalog.ts or any
// shipping query).
const NO_PERMS = {
  PermissionsAuthorApex: false, PermissionsCustomizeApplication: false, PermissionsManageUsers: false,
  PermissionsAssignPermissionSets: false,
  PermissionsDataExport: false, PermissionsViewAllUsers: false,
  PermissionsPasswordNeverExpires: false,
};

const psa = (over: Record<string, unknown> = {}) => ({
  AssigneeId: '005a',
  PermissionSetId: '0PS1',
  PermissionSet: { Name: 'Integration PS', IsOwnedByProfile: false, ...NO_PERMS, ...over },
});

describe('IntegrationLeastPrivilegeCheck — structural findings', () => {
  const check = new IntegrationLeastPrivilegeCheck();

  it('reports Author Apex on an integration account as CRITICAL', async () => {
    const r = await check.run(makeCtx({ users: SVC, psa: [psa({ PermissionsAuthorApex: true })] }));
    const f = r.findings.find((x) => x.id === 'integration-least-privilege-escalation-permissions')!;
    expect(f.riskLevel).toBe('CRITICAL');
    expect(f.affectedItems![0].label).toContain('svc.api@acme.com');
    expect(f.affectedItems![0].note).toContain('Author Apex');
  });

  it('names the grant path as a profile when the permission set is profile-owned', async () => {
    const r = await check.run(makeCtx({
      users: SVC,
      psa: [psa({ PermissionsAuthorApex: true, IsOwnedByProfile: true, Name: 'Integration Profile' })],
    }));
    const f = r.findings.find((x) => x.id === 'integration-least-privilege-escalation-permissions')!;
    expect(f.affectedItems![0].note).toContain('profile');
  });

  it('reports Data Export separately as HIGH, not as an escalation permission', async () => {
    const r = await check.run(makeCtx({ users: SVC, psa: [psa({ PermissionsDataExport: true })] }));
    expect(r.findings.map((f) => f.id)).toContain('integration-least-privilege-data-permissions');
    expect(r.findings.map((f) => f.id)).not.toContain('integration-least-privilege-escalation-permissions');
    expect(r.findings.find((f) => f.id === 'integration-least-privilege-data-permissions')!.riskLevel).toBe('HIGH');
  });

  it('reports Password Never Expires as MEDIUM hygiene', async () => {
    const r = await check.run(makeCtx({ users: SVC, psa: [psa({ PermissionsPasswordNeverExpires: true })] }));
    const f = r.findings.find((x) => x.id === 'integration-least-privilege-hygiene')!;
    expect(f.riskLevel).toBe('MEDIUM');
  });

  it('does not report Modify All Data, which integration-users owns', async () => {
    const r = await check.run(makeCtx({
      users: SVC,
      psa: [psa({ PermissionsModifyAllData: true } as Record<string, unknown>)],
    }));
    expect(r.findings.map((f) => f.id)).not.toContain('integration-least-privilege-escalation-permissions');
  });

  it('passes with -none when no integration accounts are resolved', async () => {
    const r = await check.run(makeCtx({ users: [] }));
    expect(r.findings.map((f) => f.id)).toEqual(['integration-least-privilege-none']);
    expect(r.findings[0].passed).toBe(true);
  });

  it('is inconclusive when users cannot be queried', async () => {
    const r = await check.run(makeCtx({ usersThrow: true }));
    expect(r.findings[0].id).toBe('integration-least-privilege-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('is inconclusive, not passed, when permissions cannot be queried', async () => {
    const r = await check.run(makeCtx({ users: SVC, psaThrow: true }));
    expect(r.findings[0].id).toBe('integration-least-privilege-permissions-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings.some((f) => f.passed)).toBe(false);
  });
});
