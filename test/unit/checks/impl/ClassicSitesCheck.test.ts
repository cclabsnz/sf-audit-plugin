import { jest } from '@jest/globals';
import { ClassicSitesCheck } from '../../../../src/checks/impl/ClassicSitesCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(opts: { sites?: unknown[]; throw?: boolean }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async () => {
    if (opts.throw) throw new Error('no access');
    return opts.sites ?? [];
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

const site = (over: Record<string, unknown>) => ({ Id: '0DM', Name: 's', Status: 'Active', SiteType: 'Visualforce', GuestUserId: '005', MasterLabel: 'Public Site', ...over });

describe('ClassicSitesCheck', () => {
  const check = new ClassicSitesCheck();

  it('is inconclusive when Site is inaccessible', async () => {
    const r = await check.run(makeCtx({ throw: true }));
    expect(r.findings[0].id).toBe('classic-sites-inconclusive');
  });

  it('flags active Visualforce sites as HIGH', async () => {
    const r = await check.run(makeCtx({ sites: [site({})] }));
    expect(r.findings.find((f) => f.id === 'classic-sites-active')?.riskLevel).toBe('HIGH');
  });

  it('ignores Experience Builder (Siteforce) sites', async () => {
    const r = await check.run(makeCtx({ sites: [site({ SiteType: 'Siteforce' })] }));
    expect(r.findings.some((f) => f.id === 'classic-sites-ok' && f.passed)).toBe(true);
  });

  it('ignores inactive classic sites', async () => {
    const r = await check.run(makeCtx({ sites: [site({ Status: 'Inactive' })] }));
    expect(r.findings.some((f) => f.id === 'classic-sites-ok' && f.passed)).toBe(true);
  });
});
