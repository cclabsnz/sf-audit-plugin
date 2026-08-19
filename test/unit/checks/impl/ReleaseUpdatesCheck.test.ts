import { jest } from '@jest/globals';
import { ReleaseUpdatesCheck } from '../../../../src/checks/impl/ReleaseUpdatesCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(updates: unknown[] | Error): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() =>
        updates instanceof Error ? Promise.reject(updates) : Promise.resolve(updates),
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

/** An update whose auto-activation date is `days` from now; null means undated. */
const update = (Name: string, days: number | null) => ({
  Id: `0Ru${Name}`, Name, Description: null, IsEnabled: false,
  AutoActivationDate: days === null ? null : new Date(Date.now() + days * 86_400_000).toISOString(),
});

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('ReleaseUpdatesCheck', () => {
  const check = new ReleaseUpdatesCheck();

  it('is inconclusive when CriticalUpdate cannot be read', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS')));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('release-updates-inconclusive');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('passes when nothing is pending', async () => {
    const r = await check.run(makeCtx([]));
    expect(r.findings[0].id).toBe('release-updates-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('queries only for updates that are not yet enabled', async () => {
    const ctx = makeCtx([]);
    await check.run(ctx);
    expect((ctx.tooling.query as any).mock.calls[0][0]).toMatch(/IsEnabled\s*=\s*false/i);
  });

  // The three buckets, tested either side of the 0 and 90 day boundaries.
  it.each([
    [-30, 'release-updates-overdue', 'HIGH'],
    [-1, 'release-updates-overdue', 'HIGH'],
    [30, 'release-updates-upcoming', 'MEDIUM'],
    [89, 'release-updates-upcoming', 'MEDIUM'],
    [120, 'release-updates-deferred', 'INFO'],
  ])('an update %i days out is %s (%s)', async (days, id, severity) => {
    const r = await check.run(makeCtx([update('U', days)]));
    const f = find(r, id)!;
    expect(f).toBeDefined();
    expect(f.riskLevel).toBe(severity);
    expect(r.findings).toHaveLength(1);
  });

  it('treats an update with no auto-activation date as deferred', async () => {
    const r = await check.run(makeCtx([update('Undated', null)]));
    const f = find(r, 'release-updates-deferred')!;
    expect(f.affectedItems?.[0].note).toBe('No auto-activation date');
  });

  it('reports overdue, upcoming and deferred together', async () => {
    const r = await check.run(makeCtx([
      update('Late', -10), update('Soon', 45), update('Later', 200), update('Undated', null),
    ]));
    expect(find(r, 'release-updates-overdue')!.affectedItems).toHaveLength(1);
    expect(find(r, 'release-updates-upcoming')!.affectedItems).toHaveLength(1);
    expect(find(r, 'release-updates-deferred')!.affectedItems).toHaveLength(2);
    expect(find(r, 'release-updates-ok')).toBeUndefined();
  });

  it('shows the activation date so it can be planned against', async () => {
    const r = await check.run(makeCtx([update('Soon', 45)]));
    expect(find(r, 'release-updates-upcoming')!.affectedItems?.[0].note)
      .toMatch(/Auto-activates: \d{4}-\d{2}-\d{2}/);
  });

  // Salesforce may force-activate past the date, so an overdue entry showing as disabled is
  // not proof it is still off — the remediation says to verify.
  it('tells the reader an overdue update may already have been force-activated', async () => {
    const r = await check.run(makeCtx([update('Late', -10)]));
    expect(find(r, 'release-updates-overdue')!.remediation).toMatch(/force-activated/i);
  });
});
