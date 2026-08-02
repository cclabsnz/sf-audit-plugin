import { jest } from '@jest/globals';
import { LoginAnomalyCheck } from '../../../../src/checks/impl/LoginAnomalyCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(opts: { rows?: unknown[]; throw?: boolean }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async () => {
    if (opts.throw) throw new Error('no access');
    return opts.rows ?? [];
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

const logins = (userId: string, ips: string[]) => ips.map((ip, i) => ({ UserId: userId, SourceIp: ip, LoginTime: `2026-07-0${(i % 9) + 1}T00:00:00Z` }));

describe('LoginAnomalyCheck', () => {
  const check = new LoginAnomalyCheck();

  it('is inconclusive when LoginHistory is inaccessible', async () => {
    const r = await check.run(makeCtx({ throw: true }));
    expect(r.findings[0].id).toBe('login-anomaly-inconclusive');
  });

  it('passes when there are no successful logins', async () => {
    const r = await check.run(makeCtx({ rows: [] }));
    expect(r.findings.some((f) => f.id === 'login-anomaly-none' && f.passed)).toBe(true);
  });

  it('flags a user logging in from 8+ distinct IPs as MEDIUM', async () => {
    const ips = Array.from({ length: 9 }, (_, i) => `10.0.0.${i}`);
    const r = await check.run(makeCtx({ rows: logins('005X', ips) }));
    const f = r.findings.find((x) => x.id === 'login-anomaly-multi-ip');
    expect(f?.riskLevel).toBe('MEDIUM');
    expect(f!.affectedItems?.[0].label).toContain('9 distinct IPs');
  });

  it('passes when no account exceeds the distinct-IP threshold', async () => {
    const r = await check.run(makeCtx({ rows: logins('005Y', ['1.1.1.1', '1.1.1.2', '1.1.1.3']) }));
    expect(r.findings.some((f) => f.id === 'login-anomaly-ok' && f.passed)).toBe(true);
  });
});
