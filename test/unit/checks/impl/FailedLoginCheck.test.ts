import { jest } from '@jest/globals';
import { FailedLoginCheck } from '../../../../src/checks/impl/FailedLoginCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(opts: {
  total?: number | Error;
  perUser?: Array<{ Username: string; expr0: number }> | Error;
} = {}): AuditContext {
  return {
    soql: {
      queryAll: jest.fn(),
      query: (jest.fn() as any).mockImplementation((s: string) => {
        if (/COUNT\(\)/i.test(s)) {
          return opts.total instanceof Error
            ? Promise.reject(opts.total)
            : Promise.resolve({ totalSize: opts.total ?? 0, records: [] });
        }
        return opts.perUser instanceof Error
          ? Promise.reject(opts.perUser)
          : Promise.resolve({ totalSize: 0, records: opts.perUser ?? [] });
      }),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const user = (Username: string, expr0: number) => ({ Username, expr0 });
const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('FailedLoginCheck', () => {
  const check = new FailedLoginCheck();

  it('is inconclusive when LoginHistory cannot be read', async () => {
    const r = await check.run(makeCtx({ total: new Error('INSUFFICIENT_ACCESS') }));
    expect(r.findings[0].id).toBe('failed-login-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('passes when there were no failed logins at all', async () => {
    const r = await check.run(makeCtx({ total: 0 }));
    expect(r.findings[0].id).toBe('failed-login-none');
    expect(r.findings[0].passed).toBe(true);
  });

  it('scopes both queries to failures in the last 7 days', async () => {
    const ctx = makeCtx({ total: 5 });
    await check.run(ctx);
    for (const call of (ctx.soql.query as any).mock.calls) {
      expect(call[0]).toMatch(/IsSuccess\s*=\s*false/i);
      expect(call[0]).toMatch(/LAST_N_DAYS:7/);
    }
  });

  // Thresholds: 20+ is targeted, 50+ is automated.
  it.each([
    [19, null], [20, 'failed-login-brute-force'], [49, 'failed-login-brute-force'],
    [50, 'failed-login-heavy-brute-force'], [200, 'failed-login-heavy-brute-force'],
  ])('%i failures against one account reports %s', async (count, expected) => {
    const r = await check.run(makeCtx({ total: count, perUser: [user('victim@x.com', count)] }));
    if (expected === null) {
      expect(find(r, 'failed-login-brute-force')).toBeUndefined();
      expect(find(r, 'failed-login-heavy-brute-force')).toBeUndefined();
    } else {
      expect(find(r, expected)).toBeDefined();
    }
  });

  it('rates a heavy brute-force target CRITICAL', async () => {
    const r = await check.run(makeCtx({ total: 100, perUser: [user('victim@x.com', 100)] }));
    expect(find(r, 'failed-login-heavy-brute-force')!.riskLevel).toBe('CRITICAL');
  });

  it('separates heavy targets from ordinary brute-force targets', async () => {
    const r = await check.run(makeCtx({
      total: 130, perUser: [user('heavy@x.com', 80), user('light@x.com', 25)],
    }));
    expect(find(r, 'failed-login-heavy-brute-force')!.affectedItems).toHaveLength(1);
    const light = find(r, 'failed-login-brute-force')!;
    expect(light.affectedItems).toHaveLength(1);
    expect(light.affectedItems?.[0].label).toBe('light@x.com');
  });

  // Broad credential stuffing spreads thin: many failures, no single account over threshold.
  it('flags org-wide volume when no single account stands out', async () => {
    const r = await check.run(makeCtx({
      total: 600, perUser: [user('a@x.com', 5), user('b@x.com', 4)],
    }));
    const f = find(r, 'failed-login-org-wide')!;
    expect(f.riskLevel).toBe('HIGH');
    expect(f.title).toContain('600');
  });

  it('does not raise the org-wide finding when a specific target explains the volume', async () => {
    const r = await check.run(makeCtx({ total: 600, perUser: [user('victim@x.com', 600)] }));
    expect(find(r, 'failed-login-org-wide')).toBeUndefined();
    expect(find(r, 'failed-login-heavy-brute-force')).toBeDefined();
  });

  it('passes at low volume with no concentration', async () => {
    const r = await check.run(makeCtx({ total: 8, perUser: [user('a@x.com', 3)] }));
    const f = find(r, 'failed-login-low-volume')!;
    expect(f.passed).toBe(true);
    expect(f.title).toContain('8 failed login(s)');
  });

  /**
   * The org-wide total cannot distinguish widespread user error from a concentrated attack on
   * one account. Without the per-user breakdown, "no brute-force patterns detected" is a
   * question the check could not answer, not a conclusion it reached.
   */
  it('is inconclusive when the per-account breakdown is unavailable', async () => {
    const r = await check.run(makeCtx({ total: 40, perUser: new Error('no aggregate access') }));
    const f = find(r, 'failed-login-per-user-unavailable')!;
    expect(f.inconclusive).toBe(true);
    expect(find(r, 'failed-login-low-volume')).toBeUndefined();
    expect(f.detail).toContain('could not be determined');
  });

  it('still reports org-wide volume when the breakdown is unavailable', async () => {
    const r = await check.run(makeCtx({ total: 900, perUser: new Error('no aggregate access') }));
    expect(find(r, 'failed-login-org-wide')).toBeDefined();
  });
});
