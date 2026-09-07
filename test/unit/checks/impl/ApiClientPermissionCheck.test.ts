import { jest } from '@jest/globals';
import { ApiClientPermissionCheck } from '../../../../src/checks/impl/ApiClientPermissionCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

let lastSoql = '';

function makeCtx(rows: unknown[] | Error): AuditContext {
  return {
    soql: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        lastSoql = q;
        return rows instanceof Error ? Promise.reject(rows) : Promise.resolve({ records: rows });
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

const grant = (Username: string, ownedByProfile = false, profile = 'Sales User', ps = 'API Access') => ({
  Assignee: { Id: `005${Username}`, Username, Profile: { Name: profile } },
  PermissionSet: { Name: ps, IsOwnedByProfile: ownedByProfile },
});

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('ApiClientPermissionCheck', () => {
  const check = new ApiClientPermissionCheck();

  it('passes when nobody holds the permission', async () => {
    const r = await check.run(makeCtx([]));
    expect(r.findings).toHaveLength(1);
    expect(find(r, 'api-client-permission-ok')?.passed).toBe(true);
  });

  it('reports permission-set grants as MEDIUM and names the granting set', async () => {
    const r = await check.run(makeCtx([grant('svc@acme.com', false, 'Sales User', 'Integration API')]));
    const f = find(r, 'api-client-permission-assigned');
    expect(f?.riskLevel).toBe('MEDIUM');
    expect(f!.affectedItems![0].note).toBe('via: Integration API');
  });

  it('escalates to HIGH when any grant comes from a profile', async () => {
    const r = await check.run(makeCtx([
      grant('svc@acme.com'),
      grant('rep@acme.com', true, 'Standard User'),
    ]));
    const f = find(r, 'api-client-permission-assigned');
    expect(f?.riskLevel).toBe('HIGH');
    expect(f!.affectedItems!.map((i) => i.note)).toContain('via: Profile (Standard User)');
  });

  it('falls back to "unknown" when a profile grant has no profile name', async () => {
    const r = await check.run(makeCtx([{
      Assignee: { Id: '005x', Username: 'x@acme.com' },
      PermissionSet: { Name: 'PS', IsOwnedByProfile: true },
    }]));
    expect(find(r, 'api-client-permission-assigned')!.affectedItems![0].note)
      .toBe('via: Profile (unknown)');
  });

  it('is inconclusive when the field does not exist in this edition', async () => {
    const r = await check.run(makeCtx(new Error('No such column PermissionsUseAnyApiClient')));
    expect(r.findings).toHaveLength(1);
    const f = find(r, 'api-client-permission-inconclusive');
    expect(f?.inconclusive).toBe(true);
    expect(f?.passed).toBeUndefined();
  });

  it('excludes inactive and frozen users in the query itself', async () => {
    await check.run(makeCtx([]));
    expect(lastSoql).toContain('Assignee.IsActive = true');
    // Frozen users still hold the grant but cannot use it; counting them would inflate the finding.
    expect(lastSoql).toContain('IsFrozen = true');
  });

  it('queries the API Client permission, not the API Auth one it is often confused with', async () => {
    await check.run(makeCtx([]));
    expect(lastSoql).toContain('PermissionsUseAnyApiClient');
    expect(lastSoql).not.toContain('PermissionsUseAnyApiAuth');
  });
});
