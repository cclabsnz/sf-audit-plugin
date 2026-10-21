import { jest } from '@jest/globals';
import { ConnectedAppsCheck } from '../../../../src/checks/impl/ConnectedAppsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

// Routes by API, as the org does: ConnectedApplication session settings come from the Tooling
// API, External Client Apps from the standard API.
function makeCtx(apps: unknown[] | Error, externalApps: unknown[] | Error = []): AuditContext {
  const answer = (rows: unknown[] | Error) => (rows instanceof Error ? Promise.reject(rows) : Promise.resolve(rows));
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) =>
        q.includes('FROM ExternalClientApplication') ? answer(externalApps) : Promise.reject(new Error('wrong API')),
      ),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) =>
        q.includes('FROM ConnectedApplication') ? answer(apps) : Promise.reject(new Error('wrong API')),
      ),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const app = (
  Name: string,
  { restricted = true, SessionTimeout = 15 as number | null } = {},
) => ({
  Id: `0CiA${Name}`,
  Name,
  OptionsAllowAdminApprovedUsersOnly: restricted,
  // The Tooling API returns the picklist value as a string of minutes.
  SessionTimeout: SessionTimeout === null ? null : String(SessionTimeout),
});

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('ConnectedAppsCheck', () => {
  const check = new ConnectedAppsCheck();

  it('populates connectedAppNames for the checks that depend on it', async () => {
    const ctx = makeCtx([app('Alpha'), app('Beta')]);
    await check.run(ctx);
    // connected-app-inactivity and oauth-token-inventory both read this.
    expect(ctx.cache.connectedAppNames).toEqual(['Alpha', 'Beta']);
  });

  it('flags apps that any user may self-authorise', async () => {
    const r = await check.run(makeCtx([
      app('Open', { restricted: false }),
      app('Locked'),
    ]));
    const f = find(r, 'unrestricted-connected-apps');
    expect(f?.riskLevel).toBe('MEDIUM');
    expect(f!.affectedItems!.map((i) => i.label)).toEqual(['Open']);
    expect(find(r, 'restricted-connected-apps')).toBeUndefined();
  });

  it('passes when every app is admin-approved only', async () => {
    const r = await check.run(makeCtx([app('Locked')]));
    expect(find(r, 'restricted-connected-apps')?.passed).toBe(true);
    expect(find(r, 'unrestricted-connected-apps')).toBeUndefined();
  });

  it('treats an unset or zero session timeout as inheriting the org default', async () => {
    const r = await check.run(makeCtx([
      app('Inherits', { SessionTimeout: 0 }),
      app('Unset', { SessionTimeout: null }),
    ]));
    const f = find(r, 'connected-apps-long-session-timeout');
    expect(f?.riskLevel).toBe('MEDIUM');
    expect(f!.affectedItems).toHaveLength(2);
    for (const i of f!.affectedItems!) {
      expect(i.note).toContain('inherits org default');
    }
  });

  it('flags a timeout over the 15 minute SBS-DEP-006 bar and names the value', async () => {
    const r = await check.run(makeCtx([app('Slow', { SessionTimeout: 120 })]));
    const f = find(r, 'connected-apps-long-session-timeout');
    expect(f!.affectedItems![0].note).toContain('120 min');
  });

  it('accepts exactly 15 minutes as meeting the bar', async () => {
    const r = await check.run(makeCtx([app('Boundary', { SessionTimeout: 15 })]));
    expect(find(r, 'connected-apps-long-session-timeout')).toBeUndefined();
    expect(find(r, 'connected-apps-session-timeout-ok')?.passed).toBe(true);
  });

  it('reports the app count as a metric', async () => {
    const r = await check.run(makeCtx([app('A'), app('B'), app('C')]));
    expect(r.metrics).toEqual({ connectedAppsCount: 3 });
  });

  /**
   * An org with no connected apps currently gets a green "All connected apps restrict user
   * access appropriately", worded as "All 0 connected app(s)". Nothing is unrestricted, so
   * the verdict is defensible, but the sentence reads as a positive finding about apps that
   * do not exist. Pinned as current behaviour rather than asserted as correct — see the note
   * on this test in the commit that added it.
   */
  it('emits a passing finding and no timeout finding when the org has no connected apps', async () => {
    const ctx = makeCtx([]);
    const r = await check.run(ctx);
    expect(find(r, 'restricted-connected-apps')?.passed).toBe(true);
    expect(find(r, 'connected-apps-session-timeout-ok')).toBeUndefined();
    expect(find(r, 'connected-apps-long-session-timeout')).toBeUndefined();
    expect(ctx.cache.connectedAppNames).toEqual([]);
    expect(r.metrics).toEqual({ connectedAppsCount: 0 });
  });

  it('propagates a query failure rather than reporting a clean org', async () => {
    // No try/catch here by design: CheckEngine converts a permission error into an
    // inconclusive finding centrally. What must never happen is a passing finding.
    await expect(check.run(makeCtx(new Error('INSUFFICIENT_ACCESS')))).rejects.toThrow(
      'INSUFFICIENT_ACCESS',
    );
  });

  describe('External Client Apps', () => {
    const eca = (DeveloperName: string, MasterLabel: string | null = DeveloperName) => ({ Id: `0xA${DeveloperName}`, DeveloperName, MasterLabel });

    it('lists them for manual review and never judges them on fields it cannot read', async () => {
      const r = await check.run(makeCtx([app('Legacy')], [eca('Ci_Deploy', 'CI Deploy'), eca('Mobile', null)]));
      const f = find(r, 'external-client-apps-review');
      expect(f?.riskLevel).toBe('INFO');
      expect(f?.affectedItems?.map((i) => i.label)).toEqual(['CI Deploy', 'Mobile']);
      expect(find(r, 'unrestricted-connected-apps')).toBeUndefined();
      expect(find(r, 'connected-apps-long-session-timeout')).toBeUndefined();
    });

    it('keeps them out of the connected-app name cache that the inactivity check matches against LoginHistory', async () => {
      const ctx = makeCtx([app('Legacy')], [eca('Ci_Deploy', 'CI Deploy')]);
      await check.run(ctx);
      expect(ctx.cache.connectedAppNames).toEqual(['Legacy']);
    });

    it('treats an org without External Client Apps as having none', async () => {
      const missing = Object.assign(new Error("sObject type 'ExternalClientApplication' is not supported."), { errorCode: 'INVALID_TYPE' });
      const r = await check.run(makeCtx([app('Legacy')], missing));
      expect(r.findings.some((f) => f.id.startsWith('external-client-apps'))).toBe(false);
    });

    it('reports a permission failure as inconclusive and keeps the connected-app results', async () => {
      const r = await check.run(makeCtx([app('Open', { restricted: false })], new Error('INSUFFICIENT_ACCESS_OR_READONLY')));
      expect(find(r, 'external-client-apps-inconclusive')?.inconclusive).toBe(true);
      expect(find(r, 'unrestricted-connected-apps')).toBeDefined();
      expect(r.findings.filter((f) => f.passed && f.title.includes('External'))).toHaveLength(0);
    });
  });
});
