import { jest } from '@jest/globals';
import { GuestApiAccessCheck } from '../../../../src/checks/impl/GuestApiAccessCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(opts: { guests?: unknown[]; guestsThrow?: boolean; psa?: unknown[]; psaThrow?: boolean }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async (soql: string) => {
    if (soql.includes('FROM User')) {
      if (opts.guestsThrow) throw new Error('no access');
      return opts.guests ?? [];
    }
    if (soql.includes('PermissionSetAssignment')) {
      if (opts.psaThrow) throw new Error('no access');
      return opts.psa ?? [];
    }
    return [];
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

const GUEST = [{ Id: '005g', Username: 'site guest' }];
const ps = (over: Record<string, unknown>) => ({ AssigneeId: '005g', PermissionSet: { Label: 'PS', PermissionsApiEnabled: false, PermissionsBulkApiHardDelete: false, ...over } });

describe('GuestApiAccessCheck', () => {
  const check = new GuestApiAccessCheck();

  it('passes when there are no guest users', async () => {
    const r = await check.run(makeCtx({ guests: [] }));
    expect(r.findings.some((f) => f.id === 'guest-api-access-none' && f.passed)).toBe(true);
  });

  it('flags API-enabled guests as HIGH', async () => {
    const r = await check.run(makeCtx({ guests: GUEST, psa: [ps({ PermissionsApiEnabled: true })] }));
    expect(r.findings.find((f) => f.id === 'guest-api-access-enabled')?.riskLevel).toBe('HIGH');
  });

  it('flags Bulk API Hard Delete on a guest as CRITICAL', async () => {
    const r = await check.run(makeCtx({ guests: GUEST, psa: [ps({ PermissionsBulkApiHardDelete: true })] }));
    expect(r.findings.find((f) => f.id === 'guest-api-hard-delete')?.riskLevel).toBe('CRITICAL');
  });

  it('passes when guests have no API/Bulk permissions', async () => {
    const r = await check.run(makeCtx({ guests: GUEST, psa: [ps({})] }));
    expect(r.findings.some((f) => f.id === 'guest-api-access-ok' && f.passed)).toBe(true);
  });

  it('is inconclusive when guest users cannot be queried', async () => {
    const r = await check.run(makeCtx({ guestsThrow: true }));
    expect(r.findings[0].id).toBe('guest-api-access-inconclusive');
  });
});
