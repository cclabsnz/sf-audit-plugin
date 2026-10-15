import { resolveApps } from '../../../src/apps/appResolver.js';

function soqlReturning(map: Record<string, any[]>) {
  return {
    query: async () => ({ totalSize: 0, done: true, records: [] }),
    queryAll: async (soql: string) => {
      if (soql.includes('AppMenuItem')) return map.appMenu ?? [];
      if (soql.includes('ConnectedApplication')) return map.connApp ?? [];
      if (soql.includes('LoginHistory')) return map.login ?? [];
      return [];
    },
  } as any;
}

describe('resolveApps', () => {
  it('resolves via AppMenuItem with a category tag', async () => {
    const soql = soqlReturning({ appMenu: [{ ApplicationId: '0H4app000000001', Label: 'IMMS NIS Integration' }] });
    const [r] = await resolveApps(['0H4app000000001'], soql, []);
    expect(r.name).toBe('IMMS NIS Integration');
    expect(r.confidence).toBe('resolved');
    expect(r.category).toBe('Org-custom');
  });

  it('falls back to LoginHistory correlation (inferred) for an unresolvable id', async () => {
    const soql = soqlReturning({ login: [{ Application: 'DataDog', UserId: '005U1' }] });
    const [r] = await resolveApps(['888xUNKNOWN0000'], soql, ['005U1']);
    expect(r.name).toBe('DataDog');
    expect(r.confidence).toBe('inferred');
    expect(r.category).toBe('Security-vendor');
  });

  it('emits a loud Unidentified fallback when nothing resolves', async () => {
    const soql = soqlReturning({});
    const [r] = await resolveApps(['888xUNKNOWN0000'], soql, []);
    expect(r.name).toMatch(/Unidentified connected app/);
    expect(r.category).toBe('Unidentified');
    expect(r.confidence).toBe('unidentified');
  });

  it('resolves via ExternalClientApplication', async () => {
    const soql = {
      query: async () => ({ totalSize: 0, done: true, records: [] }),
      queryAll: async (soql: string) => {
        if (soql.includes('ExternalClientApplication')) {
          return [{ Id: '0Cl000000000001', DeveloperName: 'My_ECA', MasterLabel: 'My External Client App' }];
        }
        return [];
      },
    } as any;
    const [r] = await resolveApps(['0Cl000000000001'], soql, []);
    expect(r.name).toBe('My External Client App');
    expect(r.confidence).toBe('resolved');
    expect(r.category).toBe('Org-custom');
  });

  it('resolves via LoginHistory ClientVersion when Application is generic or null', async () => {
    const soql = soqlReturning({ login: [{ Application: null, ClientVersion: 'CrowdStrike Falcon', UserId: '005U1' }] });
    const [r] = await resolveApps(['888xUNKNOWN0000'], soql, ['005U1']);
    expect(r.name).toBe('CrowdStrike Falcon');
    expect(r.confidence).toBe('inferred');
    expect(r.category).toBe('Security-vendor');
  });

  it('does not let a version-string ClientVersion break single-name inference', async () => {
    const soql = soqlReturning({ login: [{ Application: 'Vendor Sync', ClientVersion: '58.0', UserId: '005U1' }] });
    const [r] = await resolveApps(['888xUNKNOWN0000'], soql, ['005U1']);
    expect(r.name).toBe('Vendor Sync');
    expect(r.confidence).toBe('inferred');
  });

  it('ignores ClientVersion when Application already names the app', async () => {
    const soql = soqlReturning({ login: [{ Application: 'Vendor Sync', ClientVersion: 'Vendor Sync Agent', UserId: '005U1' }] });
    const [r] = await resolveApps(['888xUNKNOWN0000'], soql, ['005U1']);
    expect(r.name).toBe('Vendor Sync');
  });
});

