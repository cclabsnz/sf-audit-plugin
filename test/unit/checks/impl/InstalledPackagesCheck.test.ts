import { jest } from '@jest/globals';
import { InstalledPackagesCheck } from '../../../../src/checks/impl/InstalledPackagesCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(packages: unknown[], isSandbox: boolean, type = 'Developer Edition'): AuditContext {
  return {
    soql: {} as any,
    tooling: { query: (jest.fn() as any).mockResolvedValue(packages) } as any,
    rest: {} as any,
    orgInfo: { id: '00D000000000001', name: 'Test Org', type, isSandbox, instance: 'NA1', instanceUrl: 'https://test.my.salesforce.com' },
    cache: {} as any,
  } as any;
}

const pkg = (name: string, ns: string | null, state: string) => ({
  SubscriberPackage: { Name: name, NamespacePrefix: ns },
  SubscriberPackageVersion: { MajorVersion: 1, MinorVersion: 2, PatchVersion: 0, ReleaseState: state, PublisherName: 'Acme' },
});

describe('InstalledPackagesCheck', () => {
  const check = new InstalledPackagesCheck();

  it('reports a beta version as a LOW hygiene item, never as production', async () => {
    const r = await check.run(makeCtx([pkg('Acme Beta', 'acme', 'Beta')], true, 'Enterprise Edition'));
    const f = r.findings.find((x) => x.id === 'installed-packages-beta');
    expect(f?.riskLevel).toBe('LOW');
    expect(f?.title).toContain('sandbox');
    expect(`${f?.title} ${f?.detail}`).not.toMatch(/in production/i);
  });

  it('calls a beta in a Developer Edition org a non-production org', async () => {
    const r = await check.run(makeCtx([pkg('Acme Beta', 'acme', 'Beta')], false));
    expect(r.findings.find((x) => x.id === 'installed-packages-beta')?.title).toContain('non-production org');
  });

  it('raises no beta finding for released versions', async () => {
    const r = await check.run(makeCtx([pkg('Acme', 'acme', 'Released')], false, 'Enterprise Edition'));
    expect(r.findings.map((f) => f.id)).toEqual(['installed-packages-inventory']);
  });

  it('still flags unmanaged packages as HIGH', async () => {
    const r = await check.run(makeCtx([pkg('Local Tools', null, 'Released')], false, 'Enterprise Edition'));
    expect(r.findings.find((x) => x.id === 'installed-packages-unmanaged')?.riskLevel).toBe('HIGH');
  });
});
