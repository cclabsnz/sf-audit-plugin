import { jest } from '@jest/globals';
import { ContentLinksCheck } from '../../../../src/checks/impl/ContentLinksCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(records: unknown[] | Error): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation(() =>
        records instanceof Error ? Promise.reject(records) : Promise.resolve(records),
      ),
      query: jest.fn(),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const link = (Name: string, opts: { expiry?: boolean; password?: boolean; ageDays?: number } = {}) => ({
  Id: `05D${Name}`, Name, ContentDocumentId: `069${Name}`,
  ExpiryDate: opts.expiry === false || opts.expiry === undefined
    ? null
    : new Date(Date.now() + 30 * 86_400_000).toISOString(),
  PasswordEnabled: opts.password ?? false,
  CreatedDate: new Date(Date.now() - (opts.ageDays ?? 1) * 86_400_000).toISOString(),
});

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('ContentLinksCheck', () => {
  const check = new ContentLinksCheck();

  it('is inconclusive when ContentDistribution cannot be read', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS')));
    expect(r.findings[0].id).toBe('content-links-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('passes when there are no public links', async () => {
    const r = await check.run(makeCtx([]));
    expect(r.findings[0].id).toBe('content-links-none');
    expect(r.findings[0].passed).toBe(true);
  });

  it('only considers public links', async () => {
    const ctx = makeCtx([]);
    await check.run(ctx);
    expect((ctx.soql.queryAll as any).mock.calls[0][0]).toMatch(/IsPublic\s*=\s*true/i);
  });

  it('flags a link with no expiry date (SBS-FILE-001)', async () => {
    const r = await check.run(makeCtx([link('Doc', { expiry: false, password: true })]));
    expect(find(r, 'content-links-no-expiry')!.riskLevel).toBe('MEDIUM');
  });

  it('escalates to HIGH beyond 20 links with no expiry', async () => {
    const many = Array.from({ length: 21 }, (_, i) => link(`D${i}`, { expiry: false, password: true }));
    expect(find(await check.run(makeCtx(many)), 'content-links-no-expiry')!.riskLevel).toBe('HIGH');

    const twenty = Array.from({ length: 20 }, (_, i) => link(`D${i}`, { expiry: false, password: true }));
    expect(find(await check.run(makeCtx(twenty)), 'content-links-no-expiry')!.riskLevel).toBe('MEDIUM');
  });

  it('flags an unprotected link at LOW (SBS-FILE-002)', async () => {
    const r = await check.run(makeCtx([link('Doc', { expiry: true, password: false })]));
    expect(find(r, 'content-links-no-password')!.riskLevel).toBe('LOW');
  });

  // Stale means old AND unbounded — an old link that expires is not a problem.
  it('flags only old links that also lack an expiry (SBS-FILE-003)', async () => {
    const staleOne = await check.run(makeCtx([
      link('Old', { expiry: false, password: true, ageDays: 120 }),
    ]));
    expect(find(staleOne, 'content-links-stale')!.riskLevel).toBe('MEDIUM');

    const oldButBounded = await check.run(makeCtx([
      link('Old', { expiry: true, password: true, ageDays: 120 }),
    ]));
    expect(find(oldButBounded, 'content-links-stale')).toBeUndefined();

    const recentUnbounded = await check.run(makeCtx([
      link('New', { expiry: false, password: true, ageDays: 10 }),
    ]));
    expect(find(recentUnbounded, 'content-links-stale')).toBeUndefined();
  });

  it('passes only when every link has an expiry and a password', async () => {
    const r = await check.run(makeCtx([link('Good', { expiry: true, password: true })]));
    expect(r.findings[0].id).toBe('content-links-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('reports all three controls together for one bad link', async () => {
    const r = await check.run(makeCtx([link('Bad', { expiry: false, password: false, ageDays: 200 })]));
    const ids = r.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining([
      'content-links-no-expiry', 'content-links-no-password', 'content-links-stale',
    ]));
    expect(ids).not.toContain('content-links-ok');
  });

  it('caps each list at 50 while counting them all', async () => {
    const many = Array.from({ length: 60 }, (_, i) => link(`D${i}`, { expiry: false, password: false }));
    const r = await check.run(makeCtx(many));
    const f = find(r, 'content-links-no-expiry')!;
    expect(f.title).toContain('60 public content link(s)');
    expect(f.affectedItems).toHaveLength(50);
  });
});
