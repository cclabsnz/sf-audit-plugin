import { jest } from '@jest/globals';
import { MfaRegistrationCheck } from '../../../../src/checks/impl/MfaRegistrationCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

describe('MfaRegistrationCheck', () => {
  it('counts active users without the reserved expr0 alias', async () => {
    const ctx = {
      soql: {
        query: (jest.fn() as any).mockResolvedValue({ totalSize: 1, done: true, records: [{ expr0: 0 }] }),
        queryAll: (jest.fn() as any).mockResolvedValue([]),
      },
      tooling: {},
      rest: {},
      orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
      cache: {},
    } as unknown as AuditContext;
    await new MfaRegistrationCheck().run(ctx);
    const q = (ctx.soql.query as any).mock.calls[0][0] as string;
    expect(q).toMatch(/^SELECT COUNT\(Id\) FROM User/);
    expect(q).not.toMatch(/expr0/);
  });

  // The audit user is itself an active standard user, so a count of 0 is a visibility problem:
  // inconclusive, never "All 0 users have registered MFA".
  it('is inconclusive when no active standard user is visible', async () => {
    const ctx = {
      soql: {
        query: (jest.fn() as any).mockResolvedValue({ totalSize: 1, done: true, records: [{ expr0: 0 }] }),
        queryAll: (jest.fn() as any).mockResolvedValue([]),
      },
      tooling: {}, rest: {},
      orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
      cache: {},
    } as unknown as AuditContext;
    const [finding] = (await new MfaRegistrationCheck().run(ctx)).findings;
    expect(finding.id).toBe('mfa-registration-no-users-visible');
    expect(finding.inconclusive).toBe(true);
    expect(finding.passed).toBeUndefined();
    expect(finding.title).not.toMatch(/All 0/);
  });
  // Registrations must cover the same users as the count (active, unfrozen), all of them.
  it('drops frozen users from registrations and reads every page', async () => {
    const queryAll = (jest.fn() as any).mockImplementation(async (q: string) => {
      if (/FROM UserLogin/.test(q)) return [{ UserId: '005frozen' }];
      return [
        { UserId: '005a', User: { Username: 'a', Profile: { Name: 'P' } }, HasTotp: true },
        { UserId: '005frozen', User: { Username: 'f', Profile: { Name: 'P' } }, HasTotp: true },
      ];
    });
    const ctx = {
      soql: {
        query: (jest.fn() as any).mockResolvedValue({ totalSize: 1, done: true, records: [{ expr0: 2 }] }),
        queryAll,
      },
      tooling: {}, rest: {},
      orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
      cache: {} as any,
    } as unknown as AuditContext;
    const r = await new MfaRegistrationCheck().run(ctx);
    expect((ctx.cache as any).mfaRegistrations.map((m: any) => m.userId)).toEqual(['005a']);
    expect(r.findings[0].title).toBe('1 of 2 active user(s) have not registered any MFA method');
    const tfa = queryAll.mock.calls.map((c: any) => c[0]).find((q: string) => /TwoFactorMethodsInfo/.test(q));
    expect(tfa).not.toMatch(/LIMIT/);
  });

  // TwoFactorInfo's Type picklist holds only 'TOTP', so it never showed Salesforce Authenticator,
  // security keys or built-in authenticators; TwoFactorMethodsInfo flags each method.
  const run = async (rows: unknown[], active = 4) => {
    const queryAll = (jest.fn() as any).mockImplementation(async (q: string) => (/FROM UserLogin/.test(q) ? [] : rows));
    const ctx = {
      soql: { query: (jest.fn() as any).mockResolvedValue({ totalSize: 1, done: true, records: [{ expr0: active }] }), queryAll },
      tooling: {}, rest: {},
      orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
      cache: {} as any,
    } as unknown as AuditContext;
    const r = await new MfaRegistrationCheck().run(ctx);
    return { r, cache: (ctx.cache as any).mfaRegistrations, query: queryAll.mock.calls.map((c: any) => c[0] as string).find((q: string) => /TwoFactorMethodsInfo/.test(q)) };
  };
  const u = (id: string, flags: Record<string, boolean>) => ({ UserId: id, User: { Username: id, Profile: { Name: 'P' } }, ...flags });

  it('reads every method flag from TwoFactorMethodsInfo, not TwoFactorInfo', async () => {
    const { query } = await run([]);
    expect(query).toMatch(/FROM TwoFactorMethodsInfo/);
    for (const f of ['HasTotp', 'HasSalesforceAuthenticator', 'HasU2F', 'HasSecurityKey', 'HasBuiltInAuthenticator', 'HasUserVerifiedMobileNumber', 'HasUserVerifiedEmailAddress', 'HasTempCode']) {
      expect(query).toContain(f);
    }
  });

  it('counts authenticator, security key and built-in methods as registered, and phone, email or temp code as not', async () => {
    const { r, cache } = await run([
      u('005auth', { HasSalesforceAuthenticator: true }),
      u('005key', { HasSecurityKey: true, HasUserVerifiedMobileNumber: true }),
      u('005bio', { HasBuiltInAuthenticator: true }),
      u('005sms', { HasUserVerifiedMobileNumber: true, HasUserVerifiedEmailAddress: true }),
    ]);
    expect(r.findings[0].title).toBe('1 of 4 active user(s) have not registered any MFA method');
    expect(r.findings[0].detail).toContain('1 of the unregistered user(s) have only a verified phone number, email address or temporary code');
    // The strength check sees every method, weak ones included.
    expect(cache.find((c: any) => c.userId === '005key').methods).toEqual(['FIDO2', 'SMS_OTP']);
    expect(cache.find((c: any) => c.userId === '005sms').methods).toEqual(['SMS_OTP', 'EMAIL']);
    expect(cache.find((c: any) => c.userId === '005auth').methods).toEqual(['SALESFORCE_AUTHENTICATOR']);
  });

  it('leaves out users with no method at all', async () => {
    const { cache } = await run([u('005none', {})], 1);
    expect(cache).toEqual([]);
  });
});
