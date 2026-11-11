import { jest } from '@jest/globals';
import { GuestRecordAccessPolicyCheck } from '../../../../src/checks/impl/GuestRecordAccessPolicyCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(opts: { guests?: unknown[]; guestsThrow?: boolean }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async () => {
    if (opts.guestsThrow) throw new Error('no access');
    return opts.guests ?? [];
  });
  const toolingQuery = jest.fn() as any;
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: toolingQuery, getRecord: jest.fn() } as any,
    rest: { get: jest.fn() } as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

const GUEST = [{ Id: '005000000000001' }];

// Salesforce has enforced secure guest user record access in every org since Winter '21: from API
// 50.0, SharingSettings.enableSecureGuestAccess is always true and setting it has no effect, and
// the Release Update that carried it is gone. There is nothing to read, so the check never matches
// Release Updates by wording, which could only pick up a different guest update.
describe('GuestRecordAccessPolicyCheck', () => {
  const check = new GuestRecordAccessPolicyCheck();

  it('reports the guardrail as enforced by the platform when the org has guest users', async () => {
    const r = await check.run(makeCtx({ guests: GUEST }));
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f.id).toBe('guest-record-access-policy-enforced');
    expect(f.passed).toBe(true);
    expect(f.detail).toContain("Winter '21");
    expect(f.remediation).toContain('guest-object-exposure');
  });

  it('never reads Release Updates', async () => {
    const ctx = makeCtx({ guests: GUEST });
    await check.run(ctx);
    expect((ctx.tooling.query as jest.Mock).mock.calls).toEqual([]);
  });

  it('passes with no attack surface when there are no active guest users', async () => {
    const r = await check.run(makeCtx({ guests: [] }));
    expect(r.findings.map((f) => [f.id, f.passed])).toEqual([['guest-record-access-policy-none', true]]);
  });

  it('is inconclusive when guest users cannot be queried', async () => {
    const r = await check.run(makeCtx({ guestsThrow: true }));
    expect(r.findings[0].id).toBe('guest-record-access-policy-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('never reports the guardrail as not enforced', async () => {
    const r = await check.run(makeCtx({ guests: GUEST }));
    expect(r.findings.some((f) => /not-enforced|verify-manually/.test(f.id))).toBe(false);
  });
});
