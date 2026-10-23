// Visible tests for spec/zero-holder-permission-findings.md (INT-004). Each names its rule.
// The chain tests feed the real UsersAndAdminsCheck output: a synthetic finding with a bare id
// is exactly what let a zero-holder finding pass as evidence before.
import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import { UsersAndAdminsCheck } from '../../../src/checks/impl/UsersAndAdminsCheck.js';
import { ChainEngine } from '../../../src/chains/ChainEngine.js';
import { violationsFor } from '../../../src/findings/exitCode.js';
import { buildAuditResult } from '../../../src/findings/scoring.js';
import { DEFAULT_SCORING_CONFIG } from '../../../src/findings/ScoringConfig.js';
import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';
import { computeDiff } from '../../../src/history/DiffEngine.js';
import type { Finding } from '../../../src/findings/Finding.js';

type Perms = Partial<{ ModifyAllData: boolean; ViewAllData: boolean }>;
const IDS = ['users-modify-all-data', 'users-view-all-data'];

const row = (id: string, perms: Perms) => ({
  Assignee: { Id: id, Username: `${id}@x.com`, Name: id, Profile: { Name: 'System Administrator' } },
  PermissionSet: {
    Name: 'Admin_PS',
    IsOwnedByProfile: false,
    PermissionsModifyAllData: perms.ModifyAllData ?? false,
    PermissionsViewAllData: perms.ViewAllData ?? false,
    PermissionsManageUsers: false,
    PermissionsCustomizeApplication: false,
    PermissionsAuthorApex: false,
  },
});

interface Org {
  /** What an all-batches read returns. */
  rows: unknown[];
  /** What a single-batch read returns. Defaults to none, as a large org's first page can be. */
  firstBatch?: unknown[];
  /** What COUNT() on the assignment query reports. Defaults to rows.length (an uncapped read). */
  psaTotal?: number;
  /** The COUNT() query fails. */
  countThrows?: boolean;
  /** Every SOQL string the check sends, in order. */
  seen?: string[];
}

function makeCtx({ rows, firstBatch = [], psaTotal = rows.length, countThrows = false, seen = [] }: Org): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((s: string) => {
        seen.push(s);
        return Promise.resolve(rows);
      }),
      query: (jest.fn() as any).mockImplementation((s: string) => {
        seen.push(s);
        if (/COUNT\(\) FROM User/i.test(s)) return Promise.resolve({ totalSize: 50, done: true, records: [] });
        if (/COUNT\(\)/i.test(s)) {
          return countThrows ? Promise.reject(new Error('REQUEST_LIMIT_EXCEEDED')) : Promise.resolve({ totalSize: psaTotal, done: true, records: [] });
        }
        return Promise.resolve({ totalSize: rows.length, done: firstBatch.length === rows.length, records: firstBatch });
      }),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' },
    cache: {} as any,
  } as any;
}

async function runCheck(org: Org) {
  const r = await new UsersAndAdminsCheck().run(makeCtx(org));
  // CheckEngine stamps checkId; do the same so scoring takes its weighted branch.
  return { ...r, findings: r.findings.map((x) => ({ ...x, checkId: 'users-and-admins' })) };
}

const realFindings = async (rows: unknown[]) => (await runCheck({ rows })).findings;

function f(id: string): Finding {
  return { id, checkId: id, category: 'x', riskLevel: 'HIGH', title: id, detail: '', remediation: '' };
}

const byId = (fs: Finding[], id: string) => fs.find((x) => x.id === id);

describe('RULE-040: zero holders is reported as inconclusive', () => {
  it.each(IDS)('%s at zero is inconclusive INFO, never passed, still reported', async (id) => {
    const finding = byId(await realFindings([]), id);
    expect(finding).toBeDefined();
    expect(finding!.inconclusive).toBe(true);
    expect(finding!.passed).not.toBe(true);
    expect(finding!.riskLevel).toBe('INFO');
    expect(finding!.title).toMatch(/^Could not confirm who holds (Modify|View) All Data$/);
    expect(finding!.detail).toMatch(/cannot see PermissionSetAssignment/);
    expect(finding!.remediation).toMatch(/Re-run/);
  });

  it.each([
    ['users-modify-all-data', { ModifyAllData: true }, /^1 user\(s\) have Modify All Data/],
    ['users-view-all-data', { ViewAllData: true }, /^1 user\(s\) have View All Data/],
  ] as const)('%s with one holder is a counted pass, not inconclusive', async (id, perms, title) => {
    // RULE-074: a complete read in the lowest band is reported as passed, with its holders listed.
    const finding = byId(await realFindings([row('u1', perms)]), id);
    expect(finding!.passed).toBe(true);
    expect(finding!.inconclusive).not.toBe(true);
    expect(finding!.riskLevel).toBe('LOW');
    expect(finding!.title).toMatch(title);
    expect(finding!.detail).not.toMatch(/cannot see/);
    expect(finding!.remediation).not.toMatch(/Re-run/);
  });

  it('a zero-holder finding adds nothing to the score, even with the check weighted', async () => {
    const zero = (await realFindings([])).filter((x) => IDS.includes(x.id));
    expect(zero).toHaveLength(2);
    // A weight makes the exclusion itself what is tested: INFO alone scores 0 anyway.
    const weighted = { ...DEFAULT_SCORING_CONFIG, checkWeights: { 'users-and-admins': 10 } };
    expect(buildAuditResult(makeCtx({ rows: [] }), zero, {}, weighted).healthScore).toBe(100);
  });

  it('a zero-holder finding never trips the exit code, whatever its level', async () => {
    const zero = (await realFindings([])).filter((x) => IDS.includes(x.id));
    expect(violationsFor(zero.map((x) => ({ ...x, riskLevel: 'LOW' as const })), 'LOW')).toEqual([]);
  });
});

describe('RULE-041: a zero-holder finding never completes an attack chain', () => {
  const others: Record<string, string[]> = {
    'insider-bulk-exfil': ['data-export-weekly-export', 'event-monitoring-disabled'],
    'mfa-bypass-admin': ['internal-user-mfa-gaps'],
    'xss-to-privileged-session': ['visualforce-xss-escape-false', 'session-hardening-risks'],
    'soql-injection-read': ['soql-injection-risk'],
    'inbound-email-rce': ['inbound-email-handler-unauthenticated-execution'],
    'platform-event-priv-esc': ['platform-event-subscriber-escalation', 'guest-user-baseline'],
  };
  const gated = Object.keys(others).filter((c) => c !== 'platform-event-priv-esc');
  // Every ingredient at once, so any chain or emergent path that would accept either id has the
  // rest of what it needs.
  const everything = [...new Set(Object.values(others).flat())].map(f);
  const stepsOf = (chains: { steps: { findingId: string }[] }[]) => chains.flatMap((c) => c.steps.map((s) => s.findingId));

  it.each(gated)('%s does not fire on zero holders', async (chain) => {
    const findings = [...(await realFindings([])), ...others[chain].map(f)];
    expect(new ChainEngine().correlate(findings).map((c) => c.id)).not.toContain(chain);
  });

  it('no chain, named or emergent, uses a zero-holder finding as a step', async () => {
    const chains = new ChainEngine().correlate([...(await realFindings([])), ...everything]);
    for (const id of IDS) expect(stepsOf(chains)).not.toContain(id);
  });

  it.each(gated.filter((c) => c !== 'inbound-email-rce'))('%s fires with one View All Data holder as a step', async (chain) => {
    const findings = [...(await realFindings([row('u1', { ViewAllData: true })])), ...others[chain].map(f)];
    const hit = new ChainEngine().correlate(findings).find((c) => c.id === chain);
    expect(hit && stepsOf([hit])).toContain('users-view-all-data');
  });

  it.each(['inbound-email-rce', 'mfa-bypass-admin', 'xss-to-privileged-session', 'platform-event-priv-esc'])(
    '%s fires with one Modify All Data holder as a step', async (chain) => {
      const findings = [...(await realFindings([row('u1', { ModifyAllData: true })])), ...others[chain].map(f)];
      const hit = new ChainEngine().correlate(findings).find((c) => c.id === chain);
      expect(hit && stepsOf([hit])).toContain('users-modify-all-data');
    },
  );
});

describe('RULE-042: a partial read gives lower bounds, not passes', () => {
  const both = (n: number) => Array.from({ length: n }, (_, i) => row(`u${i}`, { ModifyAllData: true, ViewAllData: true }));

  it('counts holders that only a later batch contains', async () => {
    const early = row('u0', {});
    const late = row('u1', { ModifyAllData: true });
    const { findings } = await runCheck({ rows: [early, late], firstBatch: [early] });
    const finding = byId(findings, 'users-modify-all-data');
    expect(finding!.inconclusive).not.toBe(true);
    expect(finding!.title).toMatch(/^1 user\(s\)/);
  });

  it('the COUNT runs over exactly the row query\'s FROM and WHERE', async () => {
    const seen: string[] = [];
    await runCheck({ rows: [], seen });
    const rowQuery = seen.find((q) => q.trim().startsWith('SELECT Assignee.Id'))!;
    const countQuery = seen.find((q) => /COUNT\(\) FROM PermissionSetAssignment/i.test(q))!;
    const tail = (q: string) => q.slice(q.indexOf('FROM PermissionSetAssignment')).replace(/\s+/g, ' ').trim();
    expect(tail(countQuery)).toBe(tail(rowQuery));
    expect(tail(countQuery)).toMatch(/Assignee\.IsActive = true/);
  });

  it('a capped read with holders stays active at the lower bound\'s severity', async () => {
    const { findings } = await runCheck({ rows: both(8), psaTotal: 12000 });
    const mad = byId(findings, 'users-modify-all-data')!;
    expect(mad.inconclusive).not.toBe(true);
    expect(mad.riskLevel).toBe('CRITICAL');
    expect(mad.title).toMatch(/^At least 8 user\(s\) have Modify All Data/);
    expect(byId(findings, 'users-view-all-data')!.title).toMatch(/^At least 8 user\(s\) have View All Data/);
  });

  it('a capped read in the lowest band is a lower bound, never a pass', async () => {
    const { findings } = await runCheck({ rows: both(1), psaTotal: 12000 });
    for (const id of IDS) {
      const x = byId(findings, id)!;
      expect(x.riskLevel).toBe('LOW');
      expect(x.passed).not.toBe(true);
      expect(x.inconclusive).not.toBe(true);
      expect(x.title).toMatch(/^At least 1 user\(s\)/);
    }
  });

  it('a capped read with holders still completes a chain', async () => {
    const { findings } = await runCheck({ rows: both(1), psaTotal: 12000 });
    const chains = new ChainEngine().correlate([...findings, f('internal-user-mfa-gaps')]);
    expect(chains.map((c) => c.id)).toContain('mfa-bypass-admin');
  });

  it('qualifies the other count findings as lower bounds on a capped read', async () => {
    const rows = Array.from({ length: 6 }, (_, i) => ({
      ...row(`u${i}`, { ModifyAllData: true, ViewAllData: true }),
      PermissionSet: { ...row(`u${i}`, {}).PermissionSet, PermissionsModifyAllData: true, PermissionsViewAllData: true,
        PermissionsManageUsers: true, PermissionsCustomizeApplication: true, PermissionsAuthorApex: true },
    }));
    const { findings } = await runCheck({ rows, psaTotal: 12000 });
    for (const id of ['users-super-admin-combo', 'users-customize-application', 'users-author-apex']) {
      expect(byId(findings, id)!.title).toMatch(/^At least 6 user\(s\)/);
    }
    const exact = (await runCheck({ rows })).findings;
    expect(byId(exact, 'users-author-apex')!.title).toMatch(/^6 user\(s\)/);
  });

  it.each(IDS)('%s with zero holders on a capped read is inconclusive and says how much was read', async (id) => {
    const { findings } = await runCheck({ rows: [row('u1', {})], psaTotal: 12000 });
    const finding = byId(findings, id)!;
    expect(finding.inconclusive).toBe(true);
    expect(finding.riskLevel).toBe('INFO');
    expect(finding.title).toMatch(/read 1 of 12000 assignments$/);
    expect(finding.detail).toMatch(/holders may be in the rows not read/);
    expect(finding.remediation).toMatch(/org-max-query-limit/);
  });

  it('a partial read adds one inconclusive read-incomplete finding; a complete read does not', async () => {
    const partial = (await runCheck({ rows: both(2), psaTotal: 12000 })).findings;
    const note = byId(partial, 'users-and-admins-read-incomplete')!;
    expect(note.inconclusive).toBe(true);
    expect(note.riskLevel).toBe('INFO');
    expect(note.title).toMatch(/read 2 of 12000 assignments$/);
    expect(violationsFor(partial, 'LOW').map((x) => x.id)).not.toContain('users-and-admins-read-incomplete');
    // The capped LOW count carries the read in its detail, not only its title.
    expect(byId(partial, 'users-modify-all-data')!.detail).toMatch(/lower bound: read 2 of 12000 assignments/);
    const complete = (await runCheck({ rows: both(2) })).findings;
    expect(byId(complete, 'users-and-admins-read-incomplete')).toBeUndefined();
    expect(byId(complete, 'users-modify-all-data')!.detail).not.toMatch(/lower bound/);
  });

  it('a failed COUNT gives both visibility and row-limit advice', async () => {
    const { findings } = await runCheck({ rows: [], countThrows: true });
    const r = byId(findings, 'users-modify-all-data')!.remediation;
    expect(r).toMatch(/View Setup and Configuration/);
    expect(r).toMatch(/org-max-query-limit/);
    expect(byId(findings, 'users-and-admins-read-incomplete')!.title).toMatch(/could not be confirmed$/);
  });

  it.each([
    ['one more than read', 2, true],
    ['equal to read', 1, false],
    ['fewer than read (a race)', 0, false],
  ] as const)('a COUNT %s is partial: %s', async (_label, psaTotal, partial) => {
    const { findings } = await runCheck({ rows: both(1), psaTotal });
    expect(byId(findings, 'users-modify-all-data')!.title.startsWith('At least')).toBe(partial);
  });

  it('a failed COUNT does not fail the check, and counts become lower bounds', async () => {
    const r = await runCheck({ rows: both(1), countThrows: true });
    expect(r.metrics).toMatchObject({ totalActiveUsers: 50 });
    const mad = byId(r.findings, 'users-modify-all-data')!;
    expect(mad.inconclusive).not.toBe(true);
    expect(mad.title).toMatch(/^At least 1 user\(s\)/);
    const zero = await runCheck({ rows: [], countThrows: true });
    expect(byId(zero.findings, 'users-modify-all-data')!.title).toMatch(/could not be confirmed$/);
  });
});

describe('RULE-043: an unknown count is never shown as a number', () => {
  const result = async (org: Org) => {
    const r = await runCheck(org);
    return buildAuditResult(makeCtx(org), r.findings, r.metrics ?? {});
  };

  it('the check omits a lower-bound metric from a capped read', async () => {
    const r = await runCheck({ rows: [row('u1', { ModifyAllData: true, ViewAllData: true })], psaTotal: 12000 });
    expect(r.metrics).not.toHaveProperty('modifyAllDataUsersCount');
    expect(r.metrics).not.toHaveProperty('viewAllDataUsersCount');
    const html = new HtmlRenderer().render(await result({ rows: [row('u1', { ModifyAllData: true })], psaTotal: 12000 }));
    expect(html).toMatch(/Modify All Data<\/span><div class="metric-right"><span style="color:#8b949e;font-weight:700">unknown/);
  });

  it('an archived "0 user(s)" from v1.17 is unknown, so a later real count is not a change', async () => {
    const current = await result({ rows: [1, 2, 3].map((n) => row(`u${n}`, { ModifyAllData: true })) });
    const legacy = buildAuditResult(makeCtx({ rows: [] }), [
      { id: 'users-modify-all-data', checkId: 'users-and-admins', category: 'Access', riskLevel: 'LOW',
        title: '0 user(s) have Modify All Data permission', detail: '', remediation: '' },
    ], { modifyAllDataUsersCount: 0 });
    expect(computeDiff(legacy, current).metricDeltas.map((m) => m.key)).not.toContain('modifyAllDataUsersCount');
  });

  it('the check omits an unknown metric and keeps a known one', async () => {
    expect((await runCheck({ rows: [] })).metrics).not.toHaveProperty('modifyAllDataUsersCount');
    expect((await runCheck({ rows: [] })).metrics).not.toHaveProperty('viewAllDataUsersCount');
    const known = await runCheck({ rows: [row('u1', { ModifyAllData: true, ViewAllData: true })] });
    expect(known.metrics).toMatchObject({ modifyAllDataUsersCount: 1, viewAllDataUsersCount: 1 });
  });

  it('the HTML dashboard shows unknown, not a green 0', async () => {
    const html = new HtmlRenderer().render(await result({ rows: [] }));
    expect(html).toMatch(/Modify All Data<\/span><div class="metric-right"><span style="color:#8b949e;font-weight:700">unknown/);
    expect(html).toMatch(/View All Data<\/span><div class="metric-right"><span style="color:#8b949e;font-weight:700">unknown/);
    expect(html).not.toMatch(/Modify All Data<\/span><div class="metric-right"><span style="color:#22c55e/);
  });

  it('the HTML dashboard still shows a known count', async () => {
    const html = new HtmlRenderer().render(await result({ rows: [row('u1', { ModifyAllData: true })] }));
    expect(html).toMatch(/Modify All Data<\/span><div class="metric-right"><span style="color:#22c55e;font-weight:700">1/);
  });

  it('the history diff reports no change into or out of an unknown count', async () => {
    const known = await result({ rows: [1, 2, 3].map((n) => row(`u${n}`, { ModifyAllData: true, ViewAllData: true })) });
    const unknown = await result({ rows: [] });
    const keys = (d: ReturnType<typeof computeDiff>) => d.metricDeltas.map((m) => m.key);
    for (const d of [computeDiff(known, unknown), computeDiff(unknown, known)]) {
      expect(keys(d)).not.toContain('modifyAllDataUsersCount');
      expect(keys(d)).not.toContain('viewAllDataUsersCount');
    }
  });

  it('a count is unknown when the check did not run at all', async () => {
    const known = await result({ rows: [row('u1', { ModifyAllData: true, ViewAllData: true })] });
    // A run without users-and-admins (e.g. --checks filtered it out): the metrics default to 0.
    const skipped = buildAuditResult(makeCtx({ rows: [] }), [f('internal-user-mfa-gaps')], {});
    expect(skipped.metrics.modifyAllDataUsersCount).toBe(0);
    expect(computeDiff(known, skipped).metricDeltas.map((m) => m.key)).not.toContain('modifyAllDataUsersCount');
    expect(new HtmlRenderer().render(skipped)).toMatch(/Modify All Data<\/span><div class="metric-right"><span style="color:#8b949e;font-weight:700">unknown/);
  });

  it('an exact count of 10 or 20 is known, not mistaken for a "0 user(s)" archive', async () => {
    const holders = (n: number) => Array.from({ length: n }, (_, i) => row(`u${i}`, { ModifyAllData: true }));
    const ten = await result({ rows: holders(10) });
    const twenty = await result({ rows: holders(20) });
    expect(byId(ten.findings, 'users-modify-all-data')!.title).toMatch(/^10 user\(s\)/);
    expect(computeDiff(ten, twenty).metricDeltas.map((m) => m.key)).toContain('modifyAllDataUsersCount');
  });

  it('the history diff still reports a change between two known counts', async () => {
    const one = await result({ rows: [row('u1', { ModifyAllData: true, ViewAllData: true })] });
    const three = await result({ rows: [1, 2, 3].map((n) => row(`u${n}`, { ModifyAllData: true, ViewAllData: true })) });
    const keys = computeDiff(one, three).metricDeltas.map((m) => m.key);
    expect(keys).toContain('modifyAllDataUsersCount');
    expect(keys).toContain('viewAllDataUsersCount');
  });
});
