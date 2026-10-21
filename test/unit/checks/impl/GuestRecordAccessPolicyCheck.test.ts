import { jest } from '@jest/globals';
import { GuestRecordAccessPolicyCheck } from '../../../../src/checks/impl/GuestRecordAccessPolicyCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(opts: { guests?: unknown[]; guestsThrow?: boolean; updates?: unknown[]; updatesThrow?: boolean; releaseUpdates?: unknown[] }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async () => {
    if (opts.guestsThrow) throw new Error('no access');
    return opts.guests ?? [];
  });
  const toolingQuery = jest.fn() as any;
  toolingQuery.mockImplementation(async (q: string) => {
    if (opts.updatesThrow) throw new Error('no tooling');
    return /FROM ReleaseUpdate/.test(q) ? opts.releaseUpdates ?? [] : opts.updates ?? [];
  });
  // Orgs serving Tooling ReleaseUpdate describe it; older ones only have CriticalUpdate.
  const get = jest.fn(async (path: string) => {
    if (opts.releaseUpdates && path.includes('/tooling/sobjects/ReleaseUpdate/')) return { fields: [{ name: 'Status' }] };
    throw Object.assign(new Error('The requested resource does not exist'), { errorCode: 'NOT_FOUND' });
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: toolingQuery, getRecord: jest.fn() } as any,
    rest: { get } as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

const GUEST = [{ Id: '005000000000001' }];

describe('GuestRecordAccessPolicyCheck', () => {
  const check = new GuestRecordAccessPolicyCheck();

  it('reads Tooling ReleaseUpdate where the org serves it: Invocable means not yet enabled', async () => {
    const pending = [{ Id: 'r1', DeveloperName: 'SecureGuest', Title: 'Secure guest user record access', Description: 'Guest user record access is restricted', Status: 'Invocable' }];
    const r = await check.run(makeCtx({ guests: GUEST, releaseUpdates: pending }));
    expect(r.findings[0].id).toBe('guest-record-access-policy-not-enforced');
    const done = [{ ...pending[0], Status: 'Invoked' }];
    const r2 = await check.run(makeCtx({ guests: GUEST, releaseUpdates: done }));
    expect(r2.findings[0].id).toBe('guest-record-access-policy-enforced');
  });

  // MN-051: a revoked update is not enforced, and an unrecognised status is never read as enforced.
  it.each([
    ['Revoked', 'guest-record-access-policy-not-enforced'],
    ['Nascent', 'guest-record-access-policy-verify-manually'],
  ])('a %s release update gives %s', async (status, expected) => {
    const ru = [{ Id: 'r1', DeveloperName: 'SecureGuest', Title: 'Secure guest user record access', Description: 'Guest user record access is restricted', Status: status }];
    const r = await check.run(makeCtx({ guests: GUEST, releaseUpdates: ru }));
    expect(r.findings[0].id).toBe(expected);
    expect(r.findings.some((f) => f.id === 'guest-record-access-policy-enforced')).toBe(false);
  });

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
