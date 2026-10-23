import { jest } from '@jest/globals';
import { HighAssuranceSessionCheck } from '../../../../src/checks/impl/HighAssuranceSessionCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

// ConnectedApplication session settings come from the Tooling API; the standard API rejects
// SessionTimeout, so a standard-API query here is a bug.
function makeCtx(apps: unknown[] | Error): AuditContext {
  return {
    soql: {
      query: (jest.fn() as any).mockRejectedValue(new Error("No such column 'SessionTimeout' on entity 'ConnectedApplication'")),
      queryAll: (jest.fn() as any).mockRejectedValue(new Error('wrong API')),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) =>
        !q.includes('FROM ConnectedApplication')
          ? Promise.reject(new Error('unexpected query'))
          : apps instanceof Error
            ? Promise.reject(apps)
            : Promise.resolve(apps),
      ),
    } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
    cache: {} as any,
  } as any;
}

// The Tooling API returns the picklist value as a string of minutes, or null.
const app = (Name: string, SessionTimeout: string | null) => ({ Id: `0H4${Name}`, Name, SessionTimeout, OptionsAllowAdminApprovedUsersOnly: true });
const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('HighAssuranceSessionCheck', () => {
  const check = new HighAssuranceSessionCheck();

  it('reads minutes: a 12-hour admin app is long, a 2-hour one is not', async () => {
    const r = await check.run(makeCtx([app('Deploy Tool', '720'), app('Admin Console', '120'), app('Other', '60')]));
    const f = find(r, 'high-assurance-admin-apps-long-timeout');
    expect(f?.affectedItems?.map((i) => i.label)).toEqual(['Deploy Tool']);
    expect(f?.affectedItems?.[0].note).toContain('12h');
  });

  it('treats a null timeout as no timeout', async () => {
    const r = await check.run(makeCtx([app('Admin Console', null)]));
    expect(find(r, 'high-assurance-admin-apps-long-timeout')?.affectedItems?.[0].note).toMatch(/never expire/);
  });

  it('passes when timeouts are short', async () => {
    const r = await check.run(makeCtx([app('Admin Console', '120'), app('Other', '30')]));
    expect(find(r, 'high-assurance-session-ok')?.passed).toBe(true);
  });

  it('is inconclusive, quoting the error, when the query fails', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS: no')));
    const f = find(r, 'high-assurance-session-inaccessible');
    expect(f?.inconclusive).toBe(true);
    expect(f?.detail).toContain('INSUFFICIENT_ACCESS');
  });
});
