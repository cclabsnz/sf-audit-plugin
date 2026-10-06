import { jest } from '@jest/globals';
import { AuditTrailCheck } from '../../../../src/checks/impl/AuditTrailCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

interface AuditRow {
  CreatedDate: string;
  Action: string;
  Display: string;
  Section: string;
  CreatedBy: { Username: string };
}

const row = (section: string, display = 'changed something'): AuditRow => ({
  CreatedDate: '2026-10-01T00:00:00.000Z',
  Action: 'changedProfile',
  Display: display,
  Section: section,
  CreatedBy: { Username: 'admin@example.com' },
});

const rows = (n: number, section = 'Permission Sets'): AuditRow[] =>
  Array.from({ length: n }, (_, i) => row(section, `change ${i}`));

const deleteAssignment = (username: string, ownedByProfile = false) => ({
  Assignee: { Id: '005xx0000000001', Username: username, Profile: { Name: 'System Administrator' } },
  PermissionSet: { Name: 'Event Log Admin', IsOwnedByProfile: ownedByProfile },
});

function makeCtx(opts: {
  audit?: AuditRow[];
  loginAs?: AuditRow[];
  auditThrows?: boolean;
  loginAsThrows?: boolean;
  deleters?: unknown[];
  deletersThrow?: boolean;
}): AuditContext {
  // The two SetupAuditTrail reads are distinguished by the loginAs predicate, which only the
  // second carries. Matching on that rather than on call order keeps the mock honest if the
  // check ever reorders them.
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (soql: string) => {
    if (soql.includes('loginAs')) {
      if (opts.loginAsThrows) throw new Error('no audit trail access');
      return opts.loginAs ?? [];
    }
    if (soql.includes('SetupAuditTrail')) {
      if (opts.auditThrows) throw new Error('no audit trail access');
      return opts.audit ?? [];
    }
    return [];
  });

  const query = jest.fn() as any;
  query.mockImplementation(async (soql: string) => {
    if (soql.includes('PermissionSetAssignment')) {
      if (opts.deletersThrow) throw new Error('No such column PermissionsManageEventLogFiles');
      return { records: opts.deleters ?? [] };
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

describe('AuditTrailCheck', () => {
  const check = new AuditTrailCheck();

  describe('permission and security changes', () => {
    it('passes when no sensitive-section changes were recorded', async () => {
      const r = await check.run(makeCtx({ audit: [] }));
      const f = r.findings.find((x) => x.id === 'permission-security-changes');
      expect(f).toBeDefined();
      // An org where nothing changed must not be penalised. Without passed:true the finding
      // reaches the numerator in scoring.ts and costs health score for a clean result.
      expect(f!.passed).toBe(true);
    });

    it('does not count changes outside the sensitive sections', async () => {
      const r = await check.run(makeCtx({ audit: rows(30, 'Customize Opportunities') }));
      const f = r.findings.find((x) => x.id === 'permission-security-changes');
      expect(f!.title).toContain('0 permission');
      expect(f!.passed).toBe(true);
    });

    it('rates more than twenty sensitive changes HIGH', async () => {
      const r = await check.run(makeCtx({ audit: rows(21) }));
      const f = r.findings.find((x) => x.id === 'permission-security-changes');
      expect(f!.riskLevel).toBe('HIGH');
      expect(f!.passed).toBeFalsy();
    });

    it('rates eleven to twenty sensitive changes MEDIUM', async () => {
      const r = await check.run(makeCtx({ audit: rows(11) }));
      expect(r.findings.find((x) => x.id === 'permission-security-changes')!.riskLevel).toBe('MEDIUM');
    });

    it('rates one to ten sensitive changes LOW, and does not mark them passed', async () => {
      const r = await check.run(makeCtx({ audit: rows(1) }));
      const f = r.findings.find((x) => x.id === 'permission-security-changes');
      expect(f!.riskLevel).toBe('LOW');
      // One real change is still a change: it is reportable, so it must not read as a pass.
      expect(f!.passed).toBeFalsy();
    });

    it('counts every sensitive section, not only permission sets', async () => {
      const audit = [
        row('Profiles'),
        row('Manage Users'),
        row('Security Controls'),
        row('Password Policies'),
        row('Permission Sets'),
      ];
      const r = await check.run(makeCtx({ audit }));
      expect(r.findings.find((x) => x.id === 'permission-security-changes')!.title).toContain('5 permission');
    });

    it('caps the affected-item list at ten while reporting the true count', async () => {
      const r = await check.run(makeCtx({ audit: rows(25) }));
      const f = r.findings.find((x) => x.id === 'permission-security-changes');
      expect(f!.title).toContain('25 permission');
      expect(f!.affectedItems).toHaveLength(10);
    });
  });

  describe('Login-As events', () => {
    it('emits nothing when there were none', async () => {
      const r = await check.run(makeCtx({ loginAs: [] }));
      expect(r.findings.some((x) => x.id === 'login-as-events')).toBe(false);
    });

    it('reports them at MEDIUM when present', async () => {
      const r = await check.run(makeCtx({ loginAs: [row('Manage Users', 'logged in as user@example.com')] }));
      const f = r.findings.find((x) => x.id === 'login-as-events');
      expect(f!.riskLevel).toBe('MEDIUM');
      expect(f!.affectedItems![0].label).toContain('logged in as');
    });
  });

  describe('Manage Event Log Files (SBS-MON-002)', () => {
    it('reports users who can delete event monitoring data at HIGH', async () => {
      const r = await check.run(makeCtx({ deleters: [deleteAssignment('del@example.com')] }));
      const f = r.findings.find((x) => x.id === 'event-log-delete-permission');
      expect(f!.riskLevel).toBe('HIGH');
      expect(f!.affectedItems![0].note).toContain('Event Log Admin');
    });

    it('attributes the grant to the profile when the permission set owns one', async () => {
      const r = await check.run(makeCtx({ deleters: [deleteAssignment('del@example.com', true)] }));
      const f = r.findings.find((x) => x.id === 'event-log-delete-permission');
      expect(f!.affectedItems![0].note).toContain('System Administrator');
    });

    it('emits nothing when nobody holds the permission', async () => {
      const r = await check.run(makeCtx({ deleters: [] }));
      expect(r.findings.some((x) => x.id === 'event-log-delete-permission')).toBe(false);
    });

    it('is inconclusive when the permission cannot be queried', async () => {
      // PermissionsManageEventLogFiles does not exist without Event Monitoring, so the query
      // throws. Emitting nothing is wrong: a reader cannot distinguish "nobody can delete
      // event logs" from "we were unable to find out", and the second is not a pass.
      const r = await check.run(makeCtx({ deletersThrow: true }));
      const f = r.findings.find((x) => x.inconclusive);
      expect(f).toBeDefined();
      expect(f!.riskLevel).toBe('INFO');
      expect(f!.passed).toBeFalsy();
    });

    it('still reports the audit-trail findings when that query fails', async () => {
      const r = await check.run(makeCtx({ audit: rows(12), deletersThrow: true }));
      expect(r.findings.find((x) => x.id === 'permission-security-changes')!.riskLevel).toBe('MEDIUM');
    });
  });

  describe('when the audit trail itself cannot be read', () => {
    it('propagates rather than reporting a clean trail', async () => {
      // SetupAuditTrail needs "View Setup and Configuration". If that read fails there is no
      // basis for any finding here, so throwing is correct — the engine records the check as
      // errored instead of the report claiming nothing happened in seven days.
      await expect(check.run(makeCtx({ auditThrows: true }))).rejects.toThrow();
    });

    it('propagates a Login-As query failure for the same reason', async () => {
      await expect(check.run(makeCtx({ loginAsThrows: true }))).rejects.toThrow();
    });
  });
});
