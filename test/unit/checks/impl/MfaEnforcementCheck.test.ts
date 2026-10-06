import { jest } from '@jest/globals';
import { MfaEnforcementCheck } from '../../../../src/checks/impl/MfaEnforcementCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

const portalUser = (id: string, username: string, userType = 'PowerPartner') => ({
  Id: id,
  Username: username,
  UserType: userType,
  Profile: { Name: 'Partner Community User' },
});

const users = (n: number) =>
  Array.from({ length: n }, (_, i) => portalUser(`005xx000000000${i}`, `p${i}@example.com`));

function makeCtx(opts: {
  portal?: unknown[];
  portalThrows?: boolean;
  mfaAssigned?: string[];
  mfaThrows?: boolean;
}): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (soql: string) => {
    if (soql.includes('FROM User')) {
      if (opts.portalThrows) throw new Error('no user access');
      return opts.portal ?? [];
    }
    return [];
  });

  const query = jest.fn() as any;
  query.mockImplementation(async (soql: string) => {
    if (soql.includes('PermissionsMultiFactorForUiLogins')) {
      if (opts.mfaThrows) throw new Error('No such column PermissionsMultiFactorForUiLogins');
      return { records: (opts.mfaAssigned ?? []).map((id) => ({ AssigneeId: id })) };
    }
    return { records: [] };
  });

  return {
    soql: { query, queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: { get: jest.fn() } as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('MfaEnforcementCheck', () => {
  const check = new MfaEnforcementCheck();

  it('passes and stops when the org has no active external users', async () => {
    const r = await check.run(makeCtx({ portal: [] }));
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f.id).toBe('mfa-no-portal-users');
    expect(f.passed).toBe(true);
  });

  it('passes when every external user has the MFA permission', async () => {
    const portal = users(3);
    const r = await check.run(makeCtx({ portal, mfaAssigned: portal.map((u) => u.Id) }));
    const f = r.findings.find((x) => x.id === 'mfa-portal-users-enforced');
    expect(f!.passed).toBe(true);
    expect(f!.title).toContain('All 3');
  });

  it('reports the shortfall at MEDIUM for ten or fewer users', async () => {
    const portal = users(4);
    const r = await check.run(makeCtx({ portal, mfaAssigned: [portal[0].Id] }));
    const f = r.findings.find((x) => x.id === 'mfa-portal-users-without-enforcement');
    expect(f!.riskLevel).toBe('MEDIUM');
    expect(f!.title).toContain('3 of 4');
  });

  it('escalates to HIGH beyond ten users without MFA', async () => {
    const r = await check.run(makeCtx({ portal: users(11) }));
    const f = r.findings.find((x) => x.id === 'mfa-portal-users-without-enforcement');
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('names only the users actually missing the permission', async () => {
    const portal = users(3);
    const r = await check.run(makeCtx({ portal, mfaAssigned: [portal[1].Id] }));
    const f = r.findings.find((x) => x.id === 'mfa-portal-users-without-enforcement');
    const labels = f!.affectedItems!.map((i) => i.label);
    expect(labels).toEqual(['p0@example.com', 'p2@example.com']);
    expect(f!.detail).toContain('1 user(s) already have MFA enforced');
  });

  it('caps the named users at fifty while reporting the true count', async () => {
    const r = await check.run(makeCtx({ portal: users(60) }));
    const f = r.findings.find((x) => x.id === 'mfa-portal-users-without-enforcement');
    expect(f!.title).toContain('60 of 60');
    expect(f!.affectedItems).toHaveLength(50);
  });

  it('counts every external user type in scope', async () => {
    const portal = [
      portalUser('005xx0000000001', 'a@example.com', 'CsnOnly'),
      portalUser('005xx0000000002', 'b@example.com', 'CustomerSuccess'),
      portalUser('005xx0000000003', 'c@example.com', 'PowerPartner'),
      portalUser('005xx0000000004', 'd@example.com', 'PowerCustomerSuccess'),
      portalUser('005xx0000000005', 'e@example.com', 'SelfService'),
    ];
    const r = await check.run(makeCtx({ portal }));
    expect(r.findings.find((x) => x.id === 'mfa-portal-users-without-enforcement')!.title).toContain('5 of 5');
  });

  describe('when the MFA permission cannot be queried', () => {
    it('does not assert that the users lack MFA', async () => {
      // The permission field is absent in some editions, so this query legitimately fails.
      // Treating the failure as "none enforced" made the check state, as established fact and
      // at HIGH, that every named portal user lacks MFA — on no evidence at all. Over-reporting
      // is not the safe direction here: it produces a remediation task against real users and
      // a compliance claim about SBS-AUTH-004 that nothing supports.
      const r = await check.run(makeCtx({ portal: users(12), mfaThrows: true }));
      expect(r.findings.some((x) => x.id === 'mfa-portal-users-without-enforcement')).toBe(false);
    });

    it('declares itself inconclusive instead', async () => {
      const r = await check.run(makeCtx({ portal: users(12), mfaThrows: true }));
      const f = r.findings.find((x) => x.inconclusive);
      expect(f).toBeDefined();
      expect(f!.riskLevel).toBe('INFO');
      expect(f!.passed).toBeFalsy();
      // The user count is real and worth reporting; only the MFA status is unknown.
      expect(f!.detail).toContain('12');
    });

    it('does not claim a pass either', async () => {
      const r = await check.run(makeCtx({ portal: users(3), mfaThrows: true }));
      expect(r.findings.some((x) => x.passed)).toBe(false);
    });
  });

  it('propagates a failure to query external users at all', async () => {
    // Without the user list there is no population to reason about, so there is no finding to
    // make. Throwing lets the engine record the check as errored rather than the report
    // implying the org has no external users.
    await expect(check.run(makeCtx({ portalThrows: true }))).rejects.toThrow();
  });
});
