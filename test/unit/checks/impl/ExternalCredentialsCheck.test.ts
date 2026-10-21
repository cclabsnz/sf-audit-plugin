import { jest } from '@jest/globals';
import { ExternalCredentialsCheck } from '../../../../src/checks/impl/ExternalCredentialsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(opts: { creds?: unknown[]; throw?: boolean }): AuditContext {
  // ExternalCredential is a Tooling API object; the standard API rejects it.
  const query = jest.fn() as any;
  query.mockImplementation(async () => {
    if (opts.throw) throw new Error('no access');
    return opts.creds ?? [];
  });
  const rejected = (jest.fn() as any).mockRejectedValue(new Error("sObject type 'ExternalCredential' is not supported."));
  return {
    soql: { query: rejected, queryAll: rejected } as any,
    tooling: { query, getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('ExternalCredentialsCheck', () => {
  const check = new ExternalCredentialsCheck();

  it('is inconclusive when ExternalCredential is unsupported/inaccessible', async () => {
    const r = await check.run(makeCtx({ throw: true }));
    expect(r.findings[0].id).toBe('external-credentials-inconclusive');
  });

  it('passes when there are no external credentials', async () => {
    const r = await check.run(makeCtx({ creds: [] }));
    expect(r.findings.some((f) => f.id === 'external-credentials-none' && f.passed)).toBe(true);
  });

  it('flags no/custom authentication as MEDIUM', async () => {
    const r = await check.run(
      makeCtx({ creds: [{ Id: '1', DeveloperName: 'LegacyApi', AuthenticationProtocol: 'NoAuthentication' }] }),
    );
    expect(r.findings.find((f) => f.id === 'external-credentials-weak-auth')?.riskLevel).toBe('MEDIUM');
  });

  it('passes when all credentials use standard auth', async () => {
    const r = await check.run(makeCtx({ creds: [{ Id: '2', DeveloperName: 'Oauth', AuthenticationProtocol: 'Oauth' }] }));
    expect(r.findings.some((f) => f.id === 'external-credentials-ok' && f.passed)).toBe(true);
  });
});
