import { jest } from '@jest/globals';
import { IpRestrictionsCheck } from '../../../../src/checks/impl/IpRestrictionsCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

type Handler = (soql: string) => Promise<unknown[]>;

function makeCtx(opts: { soql?: Handler; tooling?: Handler } = {}): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((s: string) =>
        opts.soql ? opts.soql(s) : Promise.resolve([]),
      ),
      query: jest.fn(),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((s: string) =>
        opts.tooling ? opts.tooling(s) : Promise.resolve([]),
      ),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const admin = (id: string, profileId = '00eADMIN', profileName = 'System Administrator') => ({
  Id: id, ProfileId: profileId, Username: `${id}@x.com`, Profile: { Name: profileName },
});

const range = (profileId: string, StartAddress: string, EndAddress: string) => ({
  ProfileId: profileId, StartAddress, EndAddress,
});

const app = (Name: string, ipRelaxation?: string) => ({
  Id: `0CiA${Name}`, Name,
  Metadata: ipRelaxation ? { oauthConfig: { ipRelaxation } } : null,
});

/** Route SOQL by object. */
const soqlRouter = (o: { admins?: unknown[]; ranges?: unknown[]; rangeError?: boolean }): Handler => (s) => {
  if (/FROM User\b/i.test(s)) return Promise.resolve(o.admins ?? []);
  if (/FROM ProfileLoginIpRange/i.test(s)) {
    return o.rangeError ? Promise.reject(new Error('not queryable')) : Promise.resolve(o.ranges ?? []);
  }
  return Promise.resolve([]);
};

const toolingRouter = (o: { apps?: unknown[]; ranges?: unknown[]; appError?: boolean }): Handler => (s) => {
  if (/FROM ConnectedApplication/i.test(s)) {
    return o.appError ? Promise.reject(new Error('no metadata access')) : Promise.resolve(o.apps ?? []);
  }
  if (/FROM ProfileLoginIpRange/i.test(s)) return Promise.resolve(o.ranges ?? []);
  return Promise.resolve([]);
};

describe('IpRestrictionsCheck', () => {
  const check = new IpRestrictionsCheck();

  it('passes when there is nothing to flag', async () => {
    const r = await check.run(makeCtx({}));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('ip-restrictions-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags admin profiles with no IP ranges at all', async () => {
    const r = await check.run(makeCtx({ soql: soqlRouter({ admins: [admin('a1')] }) }));
    const f = r.findings.find((x) => x.id === 'admin-no-ip-restrictions');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].note).toContain('System Administrator');
  });

  it('clears an admin once their profile has any range', async () => {
    const r = await check.run(makeCtx({
      soql: soqlRouter({
        admins: [admin('a1', '00eADMIN')],
        ranges: [range('00eADMIN', '10.0.0.1', '10.0.0.50')],
      }),
    }));
    expect(r.findings.some((x) => x.id === 'admin-no-ip-restrictions')).toBe(false);
    expect(r.findings[0].id).toBe('ip-restrictions-ok');
  });

  it('only considers admins, via PermissionsModifyAllData on the profile', async () => {
    const seen: string[] = [];
    await check.run(makeCtx({ soql: (s) => { seen.push(s); return Promise.resolve([]); } }));
    const q = seen.find((s) => /FROM User\b/i.test(s))!;
    expect(q).toMatch(/Profile\.PermissionsModifyAllData\s*=\s*true/i);
    expect(q).toMatch(/IsActive\s*=\s*true/i);
  });

  // ipRelaxation drives two different severities, and 'WhiteList' is the secure value.
  it('flags ipRelaxation All as HIGH and Relax as MEDIUM', async () => {
    const r = await check.run(makeCtx({
      tooling: toolingRouter({ apps: [app('Bypasser', 'All'), app('Relaxer', 'Relax')] }),
    }));
    expect(r.findings.find((x) => x.id === 'connected-apps-bypass-ip')!.riskLevel).toBe('HIGH');
    expect(r.findings.find((x) => x.id === 'connected-apps-relax-ip')!.riskLevel).toBe('MEDIUM');
  });

  it('does not flag apps that enforce the whitelist or declare nothing', async () => {
    const r = await check.run(makeCtx({
      tooling: toolingRouter({ apps: [app('Good', 'WhiteList'), app('NoMeta')] }),
    }));
    expect(r.findings[0].id).toBe('ip-restrictions-ok');
  });

  // SBS-AUTH-003: a range wide enough to be meaningless is worse than no range, because it
  // looks like a control.
  it.each([
    ['10.0.0.0', '10.0.255.255', true],   // /16 exactly — 65,536 hosts, at the threshold
    ['10.0.0.0', '10.0.254.255', false],  // one host short of the threshold
    ['0.0.0.0', '0.0.0.1', true],         // tiny, but starts at 0.0.0.0
    ['192.168.1.1', '192.168.1.254', false],
  ])('range %s-%s flagged as broad: %s', async (start, end, expected) => {
    const r = await check.run(makeCtx({
      soql: soqlRouter({ ranges: [range('00eX', start, end)] }),
    }));
    expect(r.findings.some((x) => x.id === 'broad-ip-ranges')).toBe(expected);
  });

  it('names the profile on a broad range when it can resolve it', async () => {
    const r = await check.run(makeCtx({
      soql: soqlRouter({
        admins: [admin('a1', '00eADMIN', 'Custom Admin')],
        ranges: [range('00eADMIN', '0.0.0.0', '255.255.255.255')],
      }),
    }));
    const f = r.findings.find((x) => x.id === 'broad-ip-ranges')!;
    expect(f.affectedItems?.[0].label).toBe('Custom Admin');
    expect(f.affectedItems?.[0].note).toContain('0.0.0.0');
  });

  it('falls back to the profile id when the name is unknown', async () => {
    const r = await check.run(makeCtx({
      soql: soqlRouter({ ranges: [range('00eUNKNOWN', '0.0.0.0', '255.255.255.255')] }),
    }));
    expect(r.findings.find((x) => x.id === 'broad-ip-ranges')!.affectedItems?.[0].label)
      .toBe('00eUNKNOWN');
  });

  it('falls back to the Tooling API when ProfileLoginIpRange is not queryable via SOQL', async () => {
    const r = await check.run(makeCtx({
      soql: soqlRouter({ admins: [admin('a1', '00eADMIN')], rangeError: true }),
      tooling: toolingRouter({ ranges: [range('00eADMIN', '10.0.0.1', '10.0.0.9')] }),
    }));
    // The fallback supplied the range, so the admin is not reported as unrestricted.
    expect(r.findings.some((x) => x.id === 'admin-no-ip-restrictions')).toBe(false);
  });

  it('still reports admins when both range sources fail', async () => {
    const r = await check.run(makeCtx({
      soql: soqlRouter({ admins: [admin('a1')], rangeError: true }),
      tooling: () => Promise.reject(new Error('nope')),
    }));
    expect(r.findings.some((x) => x.id === 'admin-no-ip-restrictions')).toBe(true);
  });

  it('survives connected-app metadata being inaccessible', async () => {
    const r = await check.run(makeCtx({ tooling: toolingRouter({ appError: true }) }));
    expect(r.findings[0].id).toBe('ip-restrictions-ok');
  });

  it('reports every category together when all are present', async () => {
    const r = await check.run(makeCtx({
      soql: soqlRouter({
        admins: [admin('a1', '00eNORANGE')],
        ranges: [range('00eOTHER', '0.0.0.0', '255.255.255.255')],
      }),
      tooling: toolingRouter({ apps: [app('B', 'All'), app('R', 'Relax')] }),
    }));
    expect(r.findings.map((f) => f.id)).toEqual(expect.arrayContaining([
      'admin-no-ip-restrictions', 'connected-apps-bypass-ip',
      'connected-apps-relax-ip', 'broad-ip-ranges',
    ]));
    expect(r.findings.some((f) => f.id === 'ip-restrictions-ok')).toBe(false);
  });
});
