import { MfaMethodStrengthCheck } from '../../../../src/checks/impl/MfaMethodStrengthCheck.js';
import type { AuditContext, MfaRegistration } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(mfaRegistrations?: MfaRegistration[]): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: { mfaRegistrations } as any,
  } as any;
}

const reg = (username: string, methods: string[], profileName = 'Standard User'): MfaRegistration =>
  ({ userId: username, username, profileName, methods } as MfaRegistration);

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('MfaMethodStrengthCheck', () => {
  const check = new MfaMethodStrengthCheck();

  it('declares its cache dependency', () => {
    expect(check.dependsOnCache).toEqual(expect.arrayContaining(['mfaRegistrations']));
  });

  it('is inconclusive, not passing, when there is no registration data', async () => {
    const r = await check.run(makeCtx(undefined));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('mfa-no-data');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('treats an empty registration list the same as missing data', async () => {
    const r = await check.run(makeCtx([]));
    expect(r.findings[0].id).toBe('mfa-no-data');
  });

  // Classification follows NIST/Salesforce guidance: phishing-resistant beats TOTP beats
  // anything interceptable.
  it.each([
    ['U2F', 'phishing-resistant'], ['FIDO2', 'phishing-resistant'],
    ['WEBAUTHN', 'phishing-resistant'], ['BUILT_IN_AUTHENTICATOR', 'phishing-resistant'],
  ])('classifies %s as %s', async (method) => {
    const r = await check.run(makeCtx([reg('u', [method])]));
    expect(find(r, 'mfa-methods-summary')!.title).toContain('1 phishing-resistant');
  });

  it.each(['TOTP', 'SALESFORCE_AUTHENTICATOR'])('classifies %s as strong', async (method) => {
    const r = await check.run(makeCtx([reg('u', [method])]));
    expect(find(r, 'mfa-methods-summary')!.title).toContain('1 TOTP/authenticator');
  });

  it.each(['EMAIL', 'VERIFICATIONCODE', 'SMS_OTP'])('classifies %s as weak', async (method) => {
    const r = await check.run(makeCtx([reg('u', [method])]));
    expect(find(r, 'mfa-methods-summary')!.title).toContain('1 weak-only');
  });

  it('counts an unrecognised method as weak rather than assuming it is strong', async () => {
    const r = await check.run(makeCtx([reg('u', ['SOME_NEW_METHOD'])]));
    expect(find(r, 'mfa-methods-summary')!.title).toContain('1 weak-only');
  });

  it('counts a user with no methods at all as weak', async () => {
    const r = await check.run(makeCtx([reg('u', [])]));
    expect(find(r, 'mfa-methods-summary')!.title).toContain('1 weak-only');
  });

  // A user is rated by their strongest method, not their weakest — holding a security key
  // plus email is not a weakness.
  it('rates a user by their strongest registered method', async () => {
    const r = await check.run(makeCtx([reg('u', ['EMAIL', 'TOTP', 'FIDO2'])]));
    const title = find(r, 'mfa-methods-summary')!.title;
    expect(title).toContain('1 phishing-resistant');
    expect(title).toContain('0 weak-only');
  });

  it('flags weak-only admins as HIGH and weak-only others as MEDIUM', async () => {
    const r = await check.run(makeCtx([
      reg('boss', ['EMAIL'], 'System Administrator'),
      reg('rep', ['SMS_OTP'], 'Sales User'),
    ]));
    expect(find(r, 'mfa-admin-weak-methods')!.riskLevel).toBe('HIGH');
    expect(find(r, 'mfa-weak-only-users')!.riskLevel).toBe('MEDIUM');
  });

  it.each([
    ['System Administrator', true],
    ['Custom Admin', true],
    ['admin-lite', true],
    ['Sales User', false],
    ['Read Only', false],
  ])('profile %s counts as admin: %s', async (profileName, isAdmin) => {
    const r = await check.run(makeCtx([reg('u', ['EMAIL'], profileName)]));
    expect(find(r, 'mfa-admin-weak-methods') !== undefined).toBe(isAdmin);
  });

  it('does not flag an admin who holds a strong method', async () => {
    const r = await check.run(makeCtx([reg('boss', ['TOTP'], 'System Administrator')]));
    expect(find(r, 'mfa-admin-weak-methods')).toBeUndefined();
  });

  it('names the profile and methods so the gap is actionable', async () => {
    const r = await check.run(makeCtx([reg('boss@x.com', ['EMAIL', 'SMS_OTP'], 'System Administrator')]));
    const item = find(r, 'mfa-admin-weak-methods')!.affectedItems![0];
    expect(item.label).toBe('boss@x.com');
    expect(item.note).toContain('System Administrator');
    expect(item.note).toContain('EMAIL, SMS_OTP');
  });

  it('reports "none" rather than an empty list for a user with no methods', async () => {
    const r = await check.run(makeCtx([reg('u', [], 'System Administrator')]));
    expect(find(r, 'mfa-admin-weak-methods')!.affectedItems![0].note).toContain('methods: none');
  });

  it('caps the non-admin list at 30 while counting them all', async () => {
    const many = Array.from({ length: 35 }, (_, i) => reg(`u${i}`, ['EMAIL']));
    const r = await check.run(makeCtx(many));
    const f = find(r, 'mfa-weak-only-users')!;
    expect(f.title).toContain('35 non-admin user(s)');
    expect(f.affectedItems).toHaveLength(30);
  });

  // The positive finding only appears once adoption is genuinely a majority.
  it('passes only when more than half use phishing-resistant methods', async () => {
    const half = await check.run(makeCtx([reg('a', ['FIDO2']), reg('b', ['TOTP'])]));
    expect(find(half, 'mfa-phishing-resistant-users')).toBeUndefined();

    const majority = await check.run(makeCtx([
      reg('a', ['FIDO2']), reg('b', ['FIDO2']), reg('c', ['TOTP']),
    ]));
    const f = find(majority, 'mfa-phishing-resistant-users')!;
    expect(f.passed).toBe(true);
    expect(f.title).toContain('67%');
  });
});
