import { jest } from '@jest/globals';
import { GuestRecordAccessPolicyCheck } from '../../../../src/checks/impl/GuestRecordAccessPolicyCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(opts: { guests?: unknown[]; guestsThrow?: boolean; updates?: unknown[]; updatesThrow?: boolean }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async () => {
    if (opts.guestsThrow) throw new Error('no access');
    return opts.guests ?? [];
  });
  const toolingQuery = jest.fn() as any;
  toolingQuery.mockImplementation(async () => {
    if (opts.updatesThrow) throw new Error('no tooling');
    return opts.updates ?? [];
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: toolingQuery, getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

const GUEST = [{ Id: '005000000000001' }];

describe('GuestRecordAccessPolicyCheck', () => {
  const check = new GuestRecordAccessPolicyCheck();

  it('passes when there are no active guest users', async () => {
    const r = await check.run(makeCtx({ guests: [] }));
    expect(r.findings.some((f) => f.id === 'guest-record-access-policy-none' && f.passed)).toBe(true);
  });

  it('is inconclusive when guest users cannot be queried', async () => {
    const r = await check.run(makeCtx({ guestsThrow: true }));
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].id).toBe('guest-record-access-policy-inaccessible');
  });

  it('is inconclusive when the Tooling API cannot be queried', async () => {
    const r = await check.run(makeCtx({ guests: GUEST, updatesThrow: true }));
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].id).toBe('guest-record-access-policy-tooling-inaccessible');
  });

  it('flags HIGH when the secure-guest-access update exists but is not enabled', async () => {
    const r = await check.run(
      makeCtx({
        guests: GUEST,
        updates: [
          { Id: '01', Name: 'SecureGuestUserRecordAccess', Description: 'Secure guest user record access', IsEnabled: false },
          { Id: '02', Name: 'SomethingElse', Description: 'unrelated', IsEnabled: false },
        ],
      }),
    );
    const f = r.findings.find((x) => x.id === 'guest-record-access-policy-not-enforced');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('passes when the secure-guest-access update is enabled', async () => {
    const r = await check.run(
      makeCtx({
        guests: GUEST,
        updates: [{ Id: '01', Name: 'Secure guest user record access', Description: null, IsEnabled: true }],
      }),
    );
    const f = r.findings.find((x) => x.id === 'guest-record-access-policy-enforced');
    expect(f).toBeDefined();
    expect(f!.passed).toBe(true);
  });

  it('gives a LOW manual-verify advisory when no matching update is surfaced', async () => {
    const r = await check.run(
      makeCtx({ guests: GUEST, updates: [{ Id: '9', Name: 'EnableSomeOtherThing', Description: 'nothing to do with it', IsEnabled: false }] }),
    );
    const f = r.findings.find((x) => x.id === 'guest-record-access-policy-verify-manually');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('LOW');
  });
});
