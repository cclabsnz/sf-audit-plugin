import { jest } from '@jest/globals';
import { ExperienceCloudSiteCheck } from '../../../../src/checks/impl/ExperienceCloudSiteCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(networks: unknown[], sites: unknown[] | Error = []): AuditContext {
  return {
    soql: {
      query: jest.fn(),
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        if (/FROM Network/.test(q)) return Promise.resolve(networks);
        return sites instanceof Error ? Promise.reject(sites) : Promise.resolve(sites);
      }),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
    cache: {} as any,
  } as any;
}

const net = (Name: string, UrlPathPrefix: string | null, SelfRegProfileId: string | null = null) => ({
  Id: `0DB${Name}`, Name, Status: 'Live', UrlPathPrefix, SelfRegProfileId,
});
const site = (UrlPathPrefix: string | null, active = true) => ({
  UrlPathPrefix, GuestUserId: '005G', GuestUser: { IsActive: active },
});
const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('ExperienceCloudSiteCheck', () => {
  const check = new ExperienceCloudSiteCheck();

  it('never asks Network for a guest user field it does not have', async () => {
    const ctx = makeCtx([]);
    await check.run(ctx);
    const q = (ctx.soql.queryAll as any).mock.calls[0][0] as string;
    expect(q).toMatch(/FROM Network/);
    expect(q).not.toMatch(/GuestUserId/);
  });

  it('reads guest users from the Experience Site records', async () => {
    const ctx = makeCtx([net('Portal', 'portal')], [site('portal/s')]);
    const r = await check.run(ctx);
    const q = (ctx.soql.queryAll as any).mock.calls[1][0] as string;
    expect(q).toMatch(/FROM Site[^]*SiteType IN \('ChatterNetwork', 'ChatterNetworkPicasso'\)/);
    expect(find(r, 'experience-cloud-site-guest-access')!.affectedItems?.[0].label).toBe('Portal');
  });

  it('matches a site with the same prefix as its network', async () => {
    const r = await check.run(makeCtx([net('Portal', 'portal')], [site('portal')]));
    expect(find(r, 'experience-cloud-site-guest-access')).toBeDefined();
  });

  it('ignores an inactive guest user and a different site', async () => {
    const r = await check.run(makeCtx([net('Portal', 'portal')], [site('portal', false), site('other/s')]));
    expect(find(r, 'experience-cloud-site-guest-access')).toBeUndefined();
    expect(find(r, 'experience-cloud-site-ok')!.passed).toBe(true);
  });

  it('does not pass when the Site records cannot be read', async () => {
    const r = await check.run(makeCtx([net('Portal', 'portal')], new Error('INSUFFICIENT_ACCESS')));
    expect(find(r, 'experience-cloud-site-guest-unknown')!.inconclusive).toBe(true);
    expect(find(r, 'experience-cloud-site-ok')).toBeUndefined();
  });

  it('matches an LWR site by its vforcesite prefix', async () => {
    const r = await check.run(makeCtx([net('Portal', 'portal')], [site('portalvforcesite')]));
    expect(find(r, 'experience-cloud-site-guest-access')).toBeDefined();
  });

  it('matches a site whose label is the network name, whatever its prefix', async () => {
    const r = await check.run(makeCtx([net('Partner Portal', 'partners')], [{ ...site('custom/path'), MasterLabel: 'Partner Portal' }]));
    expect(find(r, 'experience-cloud-site-guest-access')).toBeDefined();
  });

  // MN-051: a live network whose Site cannot be found has unknown guest access, never a pass.
  it('reports a live network with no matching Site as unknown, not ok', async () => {
    const r = await check.run(makeCtx([net('Portal', 'portal')], [site('somewhere-else')]));
    expect(find(r, 'experience-cloud-site-guest-unknown')!.inconclusive).toBe(true);
    expect(find(r, 'experience-cloud-site-ok')).toBeUndefined();
  });

  it('still flags self-registration', async () => {
    const r = await check.run(makeCtx([net('Portal', 'portal', '00eX')], []));
    expect(find(r, 'experience-cloud-site-self-registration')!.riskLevel).toBe('HIGH');
  });
});
