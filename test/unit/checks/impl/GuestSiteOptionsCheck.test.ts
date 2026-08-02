import { jest } from '@jest/globals';
import { GuestSiteOptionsCheck } from '../../../../src/checks/impl/GuestSiteOptionsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(networks: unknown[]): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockResolvedValue(networks);
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('GuestSiteOptionsCheck', () => {
  const check = new GuestSiteOptionsCheck();

  it('passes when there are no Experience Cloud sites', async () => {
    const r = await check.run(makeCtx([]));
    expect(r.findings.some((f) => f.id === 'guest-site-options-none' && f.passed)).toBe(true);
  });

  it('flags guest file access as HIGH', async () => {
    const r = await check.run(
      makeCtx([{ Id: '0DB', Name: 'Portal', Status: 'Live', OptionsGuestFileAccessEnabled: true, OptionsGuestMemberVisibility: false }]),
    );
    const f = r.findings.find((x) => x.id === 'guest-site-options-file-access');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].label).toBe('Portal');
  });

  it('flags guest member visibility as MEDIUM', async () => {
    const r = await check.run(
      makeCtx([{ Id: '0DB', Name: 'Portal', Status: 'Live', OptionsGuestFileAccessEnabled: false, OptionsGuestMemberVisibility: true }]),
    );
    const f = r.findings.find((x) => x.id === 'guest-site-options-member-visibility');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
  });

  it('passes when both options are disabled', async () => {
    const r = await check.run(
      makeCtx([{ Id: '0DB', Name: 'Portal', Status: 'Live', OptionsGuestFileAccessEnabled: false, OptionsGuestMemberVisibility: false }]),
    );
    expect(r.findings.some((f) => f.id === 'guest-site-options-ok' && f.passed)).toBe(true);
  });
});
