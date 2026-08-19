import { jest } from '@jest/globals';
import { PublicGroupSharingCheck } from '../../../../src/checks/impl/PublicGroupSharingCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

type Query = (soql: string) => Promise<{ records: unknown[] }>;

function makeCtx(opts: {
  groups?: unknown[];
  query?: Query;
  healthCloudInstalled?: boolean;
} = {}): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation(() => Promise.resolve(opts.groups ?? [])),
      query: (jest.fn() as any).mockImplementation((s: string) =>
        opts.query ? opts.query(s) : Promise.resolve({ records: [] }),
      ),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: { healthCloudInstalled: opts.healthCloudInstalled } as any,
  } as any;
}

const group = (Id = '00GALL', Name = 'All Internal Users') => ({ Id, Name, Type: 'AllInternal' });

/** Return `cnt` shares on the named table, nothing elsewhere. */
const sharesOn = (table: string, cnt: number, groupId = '00GALL'): Query => (s) =>
  Promise.resolve(new RegExp(`FROM ${table}`, 'i').test(s)
    ? { records: [{ UserOrGroupId: groupId, cnt }] }
    : { records: [] });

const ALL_TABLES = ['AccountShare', 'CaseShare', 'ContactShare', 'OpportunityShare'];

describe('PublicGroupSharingCheck', () => {
  const check = new PublicGroupSharingCheck();

  it('passes when the org has no All Internal Users group', async () => {
    const r = await check.run(makeCtx({ groups: [] }));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('public-group-sharing-none');
    expect(r.findings[0].passed).toBe(true);
  });

  it('queries only for the AllInternal group type', async () => {
    const ctx = makeCtx({});
    await check.run(ctx);
    expect((ctx.soql.queryAll as any).mock.calls[0][0]).toMatch(/Type\s*=\s*'AllInternal'/i);
  });

  it('flags sharing rules that target the group', async () => {
    const r = await check.run(makeCtx({ groups: [group()], query: sharesOn('AccountShare', 7) }));
    const f = r.findings.find((x) => x.id === 'public-group-sharing-exposure');
    expect(f).toBeDefined();
    expect(f!.affectedItems?.[0].label).toContain('AccountShare');
    expect(f!.affectedItems?.[0].note).toContain('7');
  });

  it('counts distinct object types, not rule totals, in the title', async () => {
    const r = await check.run(makeCtx({
      groups: [group()],
      query: (s) => Promise.resolve(
        /FROM (AccountShare|CaseShare)/i.test(s)
          ? { records: [{ UserOrGroupId: '00GALL', cnt: 3 }] }
          : { records: [] },
      ),
    }));
    expect(r.findings[0].title).toContain('2 object type(s)');
  });

  // Health Cloud means PHI, so the same exposure carries a higher severity.
  it('raises severity from MEDIUM to HIGH when Health Cloud is installed', async () => {
    const plain = await check.run(makeCtx({ groups: [group()], query: sharesOn('AccountShare', 1) }));
    expect(plain.findings[0].riskLevel).toBe('MEDIUM');

    const hc = await check.run(makeCtx({
      groups: [group()], query: sharesOn('AccountShare', 1), healthCloudInstalled: true,
    }));
    expect(hc.findings[0].riskLevel).toBe('HIGH');
  });

  it('resolves the group name, falling back to its id', async () => {
    const named = await check.run(makeCtx({
      groups: [group('00GALL', 'Everyone Internal')], query: sharesOn('AccountShare', 1),
    }));
    expect(named.findings[0].affectedItems?.[0].label).toContain('Everyone Internal');

    const unknown = await check.run(makeCtx({
      groups: [group('00GALL')], query: sharesOn('AccountShare', 1, '00GOTHER'),
    }));
    expect(unknown.findings[0].affectedItems?.[0].label).toContain('00GOTHER');
  });

  it('restricts the count to rules, via RowCause', async () => {
    const seen: string[] = [];
    await check.run(makeCtx({
      groups: [group()],
      query: (s) => { seen.push(s); return Promise.resolve({ records: [] }); },
    }));
    expect(seen).toHaveLength(ALL_TABLES.length);
    for (const s of seen) expect(s).toMatch(/RowCause\s*=\s*'SharingRule'/i);
  });

  /**
   * "We found no sharing" and "we could not look" must not render as the same sentence. With
   * every share table unreadable the check previously emitted a pass reading "No records shared
   * to All Internal Users groups" — an assertion about data it never saw.
   */
  describe('unreadable share tables are not evidence of no sharing', () => {
    it('is inconclusive when no share table could be queried', async () => {
      const r = await check.run(makeCtx({
        groups: [group()],
        query: () => Promise.reject(new Error('INSUFFICIENT_ACCESS')),
      }));
      expect(r.findings).toHaveLength(1);
      expect(r.findings[0].id).toBe('public-group-sharing-inconclusive');
      expect(r.findings[0].inconclusive).toBe(true);
      expect(r.findings[0].passed).toBeUndefined();
      // It names what it could not read, so the gap is closable.
      for (const table of ALL_TABLES) expect(r.findings[0].detail).toContain(table);
    });

    it('scopes the pass to the tables it could actually read', async () => {
      const r = await check.run(makeCtx({
        groups: [group()],
        query: (s) => /FROM OpportunityShare/i.test(s)
          ? Promise.reject(new Error('no access'))
          : Promise.resolve({ records: [] }),
      }));
      const f = r.findings[0];
      expect(f.id).toBe('public-group-sharing-none');
      expect(f.passed).toBe(true);
      // The claim is narrowed to what was checked, and names what was not.
      expect(f.detail).toContain('OpportunityShare could not be queried');
      expect(f.detail).toContain('AccountShare');
    });

    it('still reports a real exposure even when another table is unreadable', async () => {
      const r = await check.run(makeCtx({
        groups: [group()],
        query: (s) => {
          if (/FROM AccountShare/i.test(s)) return Promise.resolve({ records: [{ UserOrGroupId: '00GALL', cnt: 4 }] });
          if (/FROM CaseShare/i.test(s)) return Promise.reject(new Error('no access'));
          return Promise.resolve({ records: [] });
        },
      }));
      expect(r.findings[0].id).toBe('public-group-sharing-exposure');
    });

    it('gives a clean, unqualified pass when everything was readable', async () => {
      const r = await check.run(makeCtx({ groups: [group()] }));
      expect(r.findings[0].passed).toBe(true);
      expect(r.findings[0].detail).not.toContain('could not be queried');
    });
  });
});
