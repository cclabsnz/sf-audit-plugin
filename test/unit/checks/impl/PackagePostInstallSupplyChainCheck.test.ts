import { jest } from '@jest/globals';
import { PackagePostInstallSupplyChainCheck } from '../../../../src/checks/impl/PackagePostInstallSupplyChainCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

// Managed-package Apex comes back with Body = '(hidden)'; only unlocked/unmanaged namespaced
// code is readable. Mocks follow that, so a test cannot pass on source the org would never return.
function makeCtx(tooling: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: { queryAll: (jest.fn() as any).mockResolvedValue([]) } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(tooling)) {
          if (q.includes(key)) return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
        }
        return Promise.resolve([]);
      }),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: '00D000000000001',
      name: 'Test Org',
      type: 'Developer Edition',
      isSandbox: false,
      instance: 'NA1',
      instanceUrl: 'https://test.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const pkg = [{ Id: '0A3a', SubscriberPackageId: '033a' }];

describe('PackagePostInstallSupplyChainCheck', () => {
  const check = new PackagePostInstallSupplyChainCheck();

  it('passes when no packages are installed', async () => {
    const r = await check.run(makeCtx({ InstalledSubscriberPackage: [] }));
    expect(r.findings.map((f) => f.id)).toEqual(['package-post-install-ok']);
  });

  it('does not report post-install scripts for readable package code that has none', async () => {
    const r = await check.run(
      makeCtx({
        InstalledSubscriberPackage: pkg,
        ApexClass: [{ Id: '01p1', Name: 'Util', NamespacePrefix: 'acme', Body: 'public class Util { }' }],
      }),
    );
    expect(r.findings.map((f) => f.id)).toEqual(['package-post-install-ok']);
  });

  it('flags a readable class that implements InstallHandler', async () => {
    const r = await check.run(
      makeCtx({
        InstalledSubscriberPackage: pkg,
        ApexClass: [
          { Id: '01p2', Name: 'PostInstall', NamespacePrefix: 'acme', Body: 'global class PostInstall implements Database.Batchable<SObject>, InstallHandler {' },
          { Id: '01p3', Name: 'Other', NamespacePrefix: 'acme', Body: 'public class Other { InstallHandler h; }' },
        ],
      }),
    );
    const f = r.findings.find((x) => x.id === 'package-post-install-system-script');
    expect(f?.affectedItems?.map((i) => i.label)).toEqual(['acme.PostInstall']);
  });

  it('reports hidden managed code as an unverifiable advisory, never as a post-install script', async () => {
    const r = await check.run(
      makeCtx({
        InstalledSubscriberPackage: pkg,
        ApexClass: [
          { Id: '01p4', Name: 'A', NamespacePrefix: 'vend', Body: '(hidden)' },
          { Id: '01p5', Name: 'B', NamespacePrefix: 'vend', Body: '(hidden)' },
        ],
      }),
    );
    expect(r.findings.map((f) => f.id)).toEqual(['package-post-install-unverifiable']);
    expect(r.findings[0].riskLevel).toBe('INFO');
    expect(r.findings[0].affectedItems).toHaveLength(1);
  });

  it('propagates a permission error on ApexClass instead of passing', async () => {
    await expect(
      check.run(makeCtx({ InstalledSubscriberPackage: pkg, ApexClass: new Error('INSUFFICIENT_ACCESS') })),
    ).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('propagates a permission error on InstalledSubscriberPackage instead of passing', async () => {
    await expect(check.run(makeCtx({ InstalledSubscriberPackage: new Error('INSUFFICIENT_ACCESS') }))).rejects.toThrow(
      'INSUFFICIENT_ACCESS',
    );
  });
});
