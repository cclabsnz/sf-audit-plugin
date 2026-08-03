import { jest } from '@jest/globals';
import { DataExportAccessCheck } from '../../../../src/checks/impl/DataExportAccessCheck.js';
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

const row = (over: Record<string, unknown>) => ({
  Id: '0PS', Label: 'X', Type: 'Regular', Profile: null,
  PermissionsDataExport: false, PermissionsApiEnabled: false, PermissionsViewAllData: false, PermissionsModifyAllData: false,
  ...over,
});

describe('DataExportAccessCheck', () => {
  const check = new DataExportAccessCheck();

  it('is inconclusive when PermissionSet is inaccessible', async () => {
    const r = await check.run(makeCtx({ throw: true }));
    expect(r.findings[0].id).toBe('data-export-access-inconclusive');
  });

  it('flags Weekly Data Export as HIGH', async () => {
    const r = await check.run(makeCtx({ rows: [row({ PermissionsDataExport: true, Type: 'Profile', Profile: { Name: 'Ops' } })] }));
    const f = r.findings.find((x) => x.id === 'data-export-weekly-export');
    expect(f?.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].label).toBe('Profile: Ops');
  });

  it('flags API + View All Data combo as HIGH', async () => {
    const r = await check.run(makeCtx({ rows: [row({ PermissionsApiEnabled: true, PermissionsViewAllData: true, Label: 'Integrations' })] }));
    expect(r.findings.find((x) => x.id === 'data-export-bulk-api-viewall')?.riskLevel).toBe('HIGH');
  });

  it('passes when no broad export capability exists', async () => {
    const r = await check.run(makeCtx({ rows: [] }));
    expect(r.findings.some((f) => f.id === 'data-export-access-ok' && f.passed)).toBe(true);
  });
});
