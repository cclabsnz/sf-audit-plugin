import { jest } from '@jest/globals';
import { ConnectedAppInactivityCheck } from '../../../../src/checks/impl/ConnectedAppInactivityCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(
  loginRows: unknown[] | Error,
  connectedAppNames: string[] | undefined = [],
): AuditContext {
  return {
    soql: {
      query: (jest.fn() as any).mockImplementation(() =>
        loginRows instanceof Error
          ? Promise.reject(loginRows)
          : Promise.resolve({ records: loginRows }),
      ),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: { connectedAppNames } as any,
  } as any;
}

const login = (Application: string, loginCount = 1) => ({ Application, loginCount });
const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('ConnectedAppInactivityCheck', () => {
  const check = new ConnectedAppInactivityCheck();

  it('passes when the org has no connected apps at all', async () => {
    const r = await check.run(makeCtx([], []));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('connected-app-inactivity-none');
    expect(r.findings[0].passed).toBe(true);
  });

  it('treats a missing cache entry the same as no apps', async () => {
    const r = await check.run(makeCtx([], undefined));
    expect(r.findings[0].id).toBe('connected-app-inactivity-none');
  });

  it('is inconclusive when LoginHistory cannot be read', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS'), ['Alpha']));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('connected-app-inactivity-inconclusive');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('splits apps into active and inactive by recent OAuth logins', async () => {
    const r = await check.run(makeCtx([login('Alpha')], ['Alpha', 'Beta']));
    expect(find(r, 'connected-app-active')!.affectedItems!.map((i) => i.label)).toEqual(['Alpha']);
    expect(find(r, 'connected-app-inactive')!.affectedItems!.map((i) => i.label)).toEqual(['Beta']);
  });

  it('matches app names case-insensitively against LoginHistory', async () => {
    const r = await check.run(makeCtx([login('alpha')], ['Alpha']));
    expect(find(r, 'connected-app-inactive')).toBeUndefined();
    expect(find(r, 'connected-app-active')).toBeDefined();
  });

  it('ignores LoginHistory rows with a null Application', async () => {
    const r = await check.run(makeCtx([{ Application: null, loginCount: 4 }], ['Alpha']));
    expect(find(r, 'connected-app-inactive')!.affectedItems!.map((i) => i.label)).toEqual(['Alpha']);
  });

  it('raises inactivity to MEDIUM only past five apps', async () => {
    const five = ['a', 'b', 'c', 'd', 'e'];
    expect(find(await check.run(makeCtx([], five)), 'connected-app-inactive')!.riskLevel).toBe('LOW');
    const six = [...five, 'f'];
    expect(find(await check.run(makeCtx([], six)), 'connected-app-inactive')!.riskLevel).toBe('MEDIUM');
  });

  it('reports active apps as INFO, not as a pass', async () => {
    const r = await check.run(makeCtx([login('Alpha')], ['Alpha']));
    const f = find(r, 'connected-app-active');
    expect(f!.riskLevel).toBe('INFO');
    expect(f!.passed).toBeUndefined();
  });

  /**
   * The load-bearing limitation, pinned so it cannot be forgotten. A refresh token is
   * exchanged for an access token without writing a LoginHistory row of LoginType 'OAuth%',
   * so an app that still holds a working credential appears here as inactive and merely LOW.
   * That is the blind spot oauth-token-inventory exists to cover, and this test documents
   * that this check does not and cannot see it from LoginHistory alone.
   */
  it('reports an app as inactive even though it may still hold a live refresh token', async () => {
    const r = await check.run(makeCtx([], ['Breached Vendor App']));
    const f = find(r, 'connected-app-inactive');
    expect(f!.riskLevel).toBe('LOW');
    expect(f!.affectedItems!.map((i) => i.label)).toEqual(['Breached Vendor App']);
    // The detail acknowledges the residual credential without measuring it.
    expect(f!.detail).toContain('still hold valid OAuth credentials');
  });
});
