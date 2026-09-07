import type { SoqlClient } from '@cclabsnz/sf-core';
import { readEffectivePermissions } from '../../../src/preflight/readPermissions.js';

const soqlReturning = (records: Array<Record<string, boolean>>): { client: SoqlClient; queries: string[] } => {
  const queries: string[] = [];
  const client = {
    query: async <T>(soql: string) => {
      queries.push(soql);
      return { totalSize: records.length, done: true, records: records as T[] };
    },
    queryAll: async <T>() => records as T[],
  } as SoqlClient;
  return { client, queries };
};

describe('readEffectivePermissions', () => {
  it('reads the caller\'s own effective permissions in a single query', async () => {
    const { client, queries } = soqlReturning([{ PermissionsApiEnabled: true }]);
    await readEffectivePermissions(client);
    expect(queries).toHaveLength(1);
    expect(queries[0]).toContain('FROM UserPermissionAccess');
  });

  it('maps present grants to true', async () => {
    const { client } = soqlReturning([{ PermissionsApiEnabled: true, PermissionsAuthorApex: true }]);
    const granted = await readEffectivePermissions(client);
    expect(granted.ApiEnabled).toBe(true);
    expect(granted.AuthorApex).toBe(true);
  });

  it('treats an absent field as not granted rather than undefined', async () => {
    const { client } = soqlReturning([{ PermissionsApiEnabled: true }]);
    const granted = await readEffectivePermissions(client);
    expect(granted.AuthorApex).toBe(false);
  });

  it('treats an empty result as nothing granted rather than throwing', async () => {
    const { client } = soqlReturning([]);
    const granted = await readEffectivePermissions(client);
    expect(Object.values(granted).every((v) => v === false)).toBe(true);
  });
});
