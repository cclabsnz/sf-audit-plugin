import { jest } from '@jest/globals';
import { RemoteSitesCheck } from '../../../../src/checks/impl/RemoteSitesCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

// RemoteProxy is served by the Tooling API, and "Disable Protocol Security" is its ProtocolMismatch
// column; the object has no DisableProtocolSecurity column.
function makeCtx(rows: unknown[]): { ctx: AuditContext; query: jest.Mock } {
  const query = (jest.fn() as any).mockImplementation((q: string) =>
    /DisableProtocolSecurity/.test(q)
      ? Promise.reject(new Error("No such column 'DisableProtocolSecurity' on entity 'RemoteProxy'"))
      : Promise.resolve(rows),
  );
  const ctx = {
    soql: {} as any,
    tooling: { query } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
    cache: {} as any,
  } as any;
  return { ctx, query };
}

const site = (SiteName: string, ProtocolMismatch: boolean) => ({
  Id: `0rp${SiteName}`, SiteName, EndpointUrl: `https://${SiteName}.example.com`, IsActive: true, ProtocolMismatch,
});

describe('RemoteSitesCheck', () => {
  const check = new RemoteSitesCheck();

  it('queries ProtocolMismatch on RemoteProxy through the Tooling API', async () => {
    const { ctx, query } = makeCtx([]);
    await check.run(ctx);
    expect(query.mock.calls[0][0]).toBe('SELECT Id, SiteName, EndpointUrl, IsActive, ProtocolMismatch FROM RemoteProxy WHERE IsActive = true');
  });

  it('flags a site with protocol security disabled as HIGH', async () => {
    const r = await check.run(makeCtx([site('plain', true), site('tls', false)]).ctx);
    const f = r.findings.find((x) => x.id === 'remote-sites-protocol-security-disabled');
    expect(f?.riskLevel).toBe('HIGH');
    expect(f?.affectedItems?.map((i) => i.label)).toEqual(['plain']);
  });

  it('passes the inventory when every site keeps protocol security', async () => {
    const { ctx } = makeCtx([site('tls', false)]);
    const r = await check.run(ctx);
    expect(r.findings.find((x) => x.id === 'remote-sites-inventory')?.passed).toBe(true);
    expect(ctx.cache.remoteSiteUrls).toEqual(['https://tls.example.com']);
  });
});
