import { jest } from '@jest/globals';
import { PackagePostInstallSupplyChainCheck } from '../../../../src/checks/impl/PackagePostInstallSupplyChainCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(toolingData: Record<string, unknown[] | Error>, soqlData: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(soqlData)) {
          if (q.includes(key)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
        }
        return Promise.resolve([]);
      }),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(toolingData)) {
          if (q.includes(key)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
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

describe('PackagePostInstallSupplyChainCheck', () => {
  const check = new PackagePostInstallSupplyChainCheck();

  it('passes when no installed packages exist', async () => {
    const ctx = makeCtx({ InstalledSubscriberPackage: [] }, {});
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('package-post-install-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags managed packages with namespaced classes and external callouts', async () => {
    const ctx = makeCtx(
      {
        InstalledSubscriberPackage: [{ Id: '0331', SubscriberPackageId: '04t1' }],
        ApexClass: [{ Id: '01pPkgClass', Name: 'PostInstall', NamespacePrefix: 'vendor_ns' }],
      },
      {
        RemoteProxy: [{ Id: '0rp1', EndpointUrl: 'https://api.vendor.com' }],
        CspTrustedSite: [{ Id: '0cs1', EndpointUrl: 'https://cdn.vendor.com' }],
      }
    );
    const r = await check.run(ctx);
    const scriptFinding = r.findings.find((x) => x.id === 'package-post-install-system-script');
    expect(scriptFinding).toBeDefined();
    expect(scriptFinding?.riskLevel).toBe('MEDIUM');

    const calloutFinding = r.findings.find((x) => x.id === 'package-post-install-callout-registered');
    expect(calloutFinding).toBeDefined();
    expect(calloutFinding?.riskLevel).toBe('MEDIUM');
  });
});
