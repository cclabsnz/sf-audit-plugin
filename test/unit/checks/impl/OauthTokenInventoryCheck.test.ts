import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

const describeFieldsMock = jest.fn<
  (rest: unknown, obj: string, preferred: readonly string[]) => Promise<string[]>
>();

jest.unstable_mockModule('@cclabsnz/sf-core', () => ({
  describeFields: describeFieldsMock,
}));

const { OauthTokenInventoryCheck, NEVER_SELECT } = await import(
  '../../../../src/checks/impl/OauthTokenInventoryCheck.js'
);

const ALL_FIELDS = ['AppName', 'UserId', 'LastUsedDate', 'UseCount', 'CreatedDate'];

let lastSoql = '';

function makeCtx(
  rows: unknown[] | Error,
  connectedAppNames: string[] = [],
): AuditContext {
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
    cache: { connectedAppNames } as any,
  } as any;
}

const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString();
const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('OauthTokenInventoryCheck', () => {
  const check = new OauthTokenInventoryCheck();

  beforeEach(() => {
    describeFieldsMock.mockReset();
    describeFieldsMock.mockResolvedValue(ALL_FIELDS);
  });

  it('is inconclusive when OauthToken cannot be described', async () => {
    describeFieldsMock.mockRejectedValue(new Error('NOT_FOUND'));
    const r = await check.run(makeCtx([]));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('oauth-token-inventory-inconclusive');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('is inconclusive when AppName is not exposed, rather than reporting a clean org', async () => {
    describeFieldsMock.mockResolvedValue(['UserId', 'LastUsedDate']);
    const r = await check.run(makeCtx([]));
    expect(r.findings[0].id).toBe('oauth-token-inventory-inconclusive');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('is inconclusive when the query is rejected', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS')));
    expect(r.findings[0].id).toBe('oauth-token-inventory-inconclusive');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('passes when no standing tokens exist', async () => {
    const r = await check.run(makeCtx([]));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('oauth-token-inventory-none');
    expect(r.findings[0].passed).toBe(true);
  });

  it('never selects token material, whatever describe offers', async () => {
    describeFieldsMock.mockResolvedValue([...ALL_FIELDS, ...NEVER_SELECT]);
    await check.run(makeCtx([{ AppName: 'App', UserId: '005a' }], ['App']));
    for (const forbidden of NEVER_SELECT) {
      expect(lastSoql).not.toContain(forbidden);
    }
  });

  it('skips the cross-reference when the connected app inventory is empty', async () => {
    const r = await check.run(
      makeCtx([{ AppName: 'Anything', UserId: '005a', LastUsedDate: daysAgo(1) }], []),
    );
    expect(find(r, 'oauth-token-unmatched-app')).toBeUndefined();
    const note = find(r, 'oauth-token-no-app-inventory');
    expect(note).toBeDefined();
    expect(note!.inconclusive).toBe(true);
    expect(note!.riskLevel).toBe('INFO');
  });

  it('does not flag first-party Salesforce clients as unmatched', async () => {
    const r = await check.run(
      makeCtx(
        [
          { AppName: 'Salesforce CLI', UserId: '005a', LastUsedDate: daysAgo(1) },
          { AppName: 'Workbench', UserId: '005b', LastUsedDate: daysAgo(1) },
        ],
        ['Some Declared App'],
      ),
    );
    expect(find(r, 'oauth-token-unmatched-app')).toBeUndefined();
    expect(find(r, 'oauth-token-inventory')!.affectedItems).toHaveLength(2);
  });

  it('flags an app holding tokens that is absent from the connected app inventory', async () => {
    const r = await check.run(
      makeCtx(
        [
          { AppName: 'Acme Vendor Sync', UserId: '005a', LastUsedDate: daysAgo(1) },
          { AppName: 'Acme Vendor Sync', UserId: '005b', LastUsedDate: daysAgo(2) },
        ],
        ['Salesforce CLI'],
      ),
    );
    const f = find(r, 'oauth-token-unmatched-app');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('MEDIUM');
    expect(f!.affectedItems).toHaveLength(1);
    expect(f!.affectedItems![0].label).toBe('Acme Vendor Sync');
    expect(f!.affectedItems![0].note).toContain('2 token(s), 2 user(s)');
  });

  it('matches app names case-insensitively against the connected app cache', async () => {
    const r = await check.run(
      makeCtx([{ AppName: 'Salesforce CLI', UserId: '005a', LastUsedDate: daysAgo(1) }], [
        'salesforce cli',
      ]),
    );
    expect(find(r, 'oauth-token-unmatched-app')).toBeUndefined();
  });

  it('flags tokens unused beyond the stale window, including those never used', async () => {
    const r = await check.run(
      makeCtx(
        [
          { AppName: 'Old Integration', UserId: '005a', LastUsedDate: daysAgo(200) },
          { AppName: 'Never Used', UserId: '005b', LastUsedDate: null },
          { AppName: 'Active', UserId: '005c', LastUsedDate: daysAgo(3) },
        ],
        ['Old Integration', 'Never Used', 'Active'],
      ),
    );
    const f = find(r, 'oauth-token-stale');
    expect(f).toBeDefined();
    const labels = f!.affectedItems!.map((i) => i.label).sort();
    expect(labels).toEqual(['Never Used', 'Old Integration']);
  });

  it('keeps the most recent last-used date when an app has several tokens', async () => {
    const r = await check.run(
      makeCtx(
        [
          { AppName: 'App', UserId: '005a', LastUsedDate: daysAgo(200) },
          { AppName: 'App', UserId: '005b', LastUsedDate: daysAgo(1) },
        ],
        ['App'],
      ),
    );
    expect(find(r, 'oauth-token-stale')).toBeUndefined();
    const inv = find(r, 'oauth-token-inventory');
    expect(inv!.affectedItems![0].note).toContain('2 token(s), 2 user(s)');
  });

  it('always emits the inventory finding as INFO', async () => {
    const r = await check.run(
      makeCtx([{ AppName: 'App', UserId: '005a', LastUsedDate: daysAgo(1) }], ['App']),
    );
    const inv = find(r, 'oauth-token-inventory');
    expect(inv).toBeDefined();
    expect(inv!.riskLevel).toBe('INFO');
    expect(inv!.title).toContain('1 app(s) hold 1 standing OAuth token(s)');
  });

  it('says so when the org exposes fewer OauthToken fields than preferred', async () => {
    describeFieldsMock.mockResolvedValue(['AppName', 'UserId']);
    const r = await check.run(
      makeCtx([{ AppName: 'App', UserId: '005a' }], ['App']),
    );
    expect(find(r, 'oauth-token-inventory')!.detail).toContain('2 of 5 OauthToken fields');
  });

  it('ignores rows with a blank app name', async () => {
    const r = await check.run(
      makeCtx([{ AppName: '  ', UserId: '005a' }, { AppName: 'App', UserId: '005b' }], ['App']),
    );
    expect(find(r, 'oauth-token-inventory')!.title).toContain('1 app(s)');
  });
});
