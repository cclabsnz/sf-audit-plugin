// IST visible rule tests for spec/severity-and-grade.md (RULE-064..070, INT-011).
import { jest } from '@jest/globals';
import type { AuditContext } from '@cclabsnz/sf-core';
import { buildAuditResult } from '../../../src/findings/scoring.js';
import type { Finding } from '../../../src/findings/Finding.js';
import type { AttackChain } from '../../../src/chains/AttackChain.js';
import { UsersAndAdminsCheck } from '../../../src/checks/impl/UsersAndAdminsCheck.js';
import { CertificateExpiryCheck } from '../../../src/checks/impl/CertificateExpiryCheck.js';
import { ApexSharingCheck } from '../../../src/checks/impl/ApexSharingCheck.js';
import { MarkdownRenderer } from '../../../src/renderers/MarkdownRenderer.js';
import { HtmlRenderer } from '../../../src/renderers/HtmlRenderer.js';

const ORG = { id: 'o', name: 'n', type: 'Enterprise Edition', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com' };

function ctx(over: Partial<AuditContext> = {}, isSandbox = false): AuditContext {
  return { soql: {} as any, tooling: {} as any, rest: {} as any, orgInfo: { ...ORG, isSandbox }, cache: {} as any, ...over } as any;
}

const f = (riskLevel: Finding['riskLevel'], id: string, extra: Partial<Finding> = {}): Finding => ({
  id, checkId: id, category: 'T', riskLevel, title: id, detail: 'd', remediation: 'r', ...extra,
});

const chain = (severity: AttackChain['severity'], confidence: AttackChain['confidence']): AttackChain =>
  ({ id: `c-${confidence}`, title: 't', severity, confidence, steps: [] } as unknown as AttackChain);

describe('RULE-064 unassessed findings carry no weight in the health score (MN-054)', () => {
  it('adding inconclusive or not-assessed findings leaves the score unchanged', () => {
    const base = [f('HIGH', 'h'), f('LOW', 'p', { passed: true })];
    const withBlind = [
      ...base,
      ...Array.from({ length: 20 }, (_, i) => f('INFO', `x${i}`, { inconclusive: true, notAssessed: true })),
      f('INFO', 'na', { notAssessed: true }),
    ];
    expect(buildAuditResult(ctx(), withBlind, {}).healthScore).toBe(buildAuditResult(ctx(), base, {}).healthScore);
  });

  it('passed findings still dilute the penalty', () => {
    const one = buildAuditResult(ctx(), [f('HIGH', 'h')], {}).healthScore;
    const diluted = buildAuditResult(ctx(), [f('HIGH', 'h'), f('LOW', 'p', { passed: true })], {}).healthScore;
    expect(diluted).toBeGreaterThan(one);
  });
});

describe('RULE-065 every grade comes with its reason (MN-055)', () => {
  it.each([
    [[f('CRITICAL', 'c1'), f('CRITICAL', 'c2')], 'F', /2 CRITICAL/],
    [[f('HIGH', 'h1'), f('HIGH', 'h2'), ...Array.from({ length: 10 }, (_, i) => f('LOW', `p${i}`, { passed: true }))], 'C', /C: 2 HIGH findings \(B allows at most 1\)/],
    [[], 'A', /score/i],
  ])('names what set the grade', (findings, grade, reason) => {
    const r = buildAuditResult(ctx(), findings as Finding[], {});
    if (grade) expect(r.grade).toBe(grade);
    expect(r.gradeReason).toMatch(reason as RegExp);
  });

  it('names the coverage cap when coverage lowered the grade', () => {
    const findings = [f('LOW', 'ok', { passed: true }), f('INFO', 'blind', { inconclusive: true, notAssessed: true })];
    const r = buildAuditResult(ctx(), findings, {});
    expect(r.coverage?.gradeCapped).toBe(true);
    expect(r.gradeReason).toMatch(/coverage/i);
  });

  it('says when attack chains are part of the count', () => {
    const r = buildAuditResult(ctx(), [f('CRITICAL', 'c1')], {}, undefined, [chain('CRITICAL', 'named')]);
    expect(r.gradeReason).toBe('F: 2 CRITICAL (1 finding, 1 attack chain) (D allows none)');
  });

  it('the Markdown report prints the reason next to the grade', () => {
    const r = buildAuditResult(ctx(), [f('CRITICAL', 'c1')], {});
    const md = new MarkdownRenderer().render(r);
    expect(md).toContain(`**Grade:** F (${r.gradeReason})`);
  });
});

describe('RULE-066 / RULE-067 admin-count findings (MN-052)', () => {
  const row = (id: string, perms: { MAD?: boolean; VAD?: boolean; MU?: boolean }) => ({
    Assignee: { Id: id, Username: `${id}@x.com`, Name: id, Profile: { Name: 'System Administrator' } },
    PermissionSet: {
      Name: 'PS', IsOwnedByProfile: false,
      PermissionsModifyAllData: perms.MAD ?? false, PermissionsViewAllData: perms.VAD ?? false,
      PermissionsManageUsers: perms.MU ?? false, PermissionsCustomizeApplication: false, PermissionsAuthorApex: false,
    },
  });
  const run = (rows: unknown[], isSandbox = false) =>
    new UsersAndAdminsCheck().run(
      ctx(
        {
          soql: {
            queryAll: (jest.fn() as any).mockResolvedValue(rows),
            // The PermissionSetAssignment COUNT() matches the rows read, so the read is complete.
            query: (jest.fn() as any).mockImplementation((s: string) =>
              Promise.resolve({ totalSize: /PermissionSetAssignment/.test(s) ? rows.length : 50, records: [] }),
            ),
          } as any,
        },
        isSandbox,
      ),
    );
  const sev = (r: { findings: Finding[] }, id: string) => r.findings.find((x) => x.id === id)?.riskLevel;
  const superAdmins = (n: number) => Array.from({ length: n }, (_, i) => row(`s${i}`, { MAD: true, VAD: true, MU: true }));
  const madOnly = (n: number) => Array.from({ length: n }, (_, i) => row(`m${i}`, { MAD: true }));

  it('RULE-066: Modify All Data held only by super-admins does not escalate again', async () => {
    const r = await run(superAdmins(9));
    expect(sev(r, 'users-super-admin-combo')).toBe('CRITICAL');
    expect(sev(r, 'users-modify-all-data')).toBe('LOW');
    expect(r.findings.find((x) => x.id === 'users-modify-all-data')!.affectedItems).toHaveLength(9);
  });

  it('RULE-066: holders outside the super-admin finding still escalate', async () => {
    const r = await run([...superAdmins(2), ...madOnly(6)]);
    expect(sev(r, 'users-modify-all-data')).toBe('CRITICAL');
  });

  it('RULE-067: in a sandbox both are at most HIGH, and say why', async () => {
    const r = await run([...superAdmins(9), ...madOnly(6)], true);
    expect(sev(r, 'users-super-admin-combo')).toBe('HIGH');
    expect(sev(r, 'users-modify-all-data')).toBe('HIGH');
    expect(r.findings.find((x) => x.id === 'users-super-admin-combo')!.detail).toMatch(/sandbox/i);
  });
});

describe('RULE-068 an expiring certificate is HIGH, not CRITICAL (MN-053)', () => {
  it.each([[-3], [10]])('expires in %i days', async (days) => {
    const certs = [{ Id: '0PEa', MasterLabel: 'a', DeveloperName: 'a', ExpirationDate: new Date(Date.now() + days * 86_400_000).toISOString() }];
    const r = await new CertificateExpiryCheck().run(
      ctx({ tooling: { query: (jest.fn() as any).mockResolvedValue(certs), getRecord: jest.fn() } as any }),
    );
    const finding = r.findings.find((x) => x.id === 'certificate-expiring-critical');
    expect(finding?.riskLevel).toBe('HIGH');
  });
});

describe('RULE-069 externally callable Apex is CRITICAL only when it declares without sharing', () => {
  const run = (bodies: Array<{ name: string; body: string }>) =>
    new ApexSharingCheck().run(
      ctx({ tooling: { query: (jest.fn() as any).mockResolvedValue([]), getRecord: jest.fn() } as any, cache: { apexBodies: bodies } as any }),
    );
  const exposed = (r: { findings: Finding[] }) => r.findings.find((x) => x.id === 'portal-exposed-apex-without-sharing');

  it('no declaration only: HIGH', async () => {
    const r = await run([{ name: 'A', body: 'public class A { @AuraEnabled public static void go() {} }' }]);
    expect(exposed(r)?.riskLevel).toBe('HIGH');
  });

  it('any explicit without sharing: CRITICAL', async () => {
    const r = await run([
      { name: 'A', body: 'public class A { @AuraEnabled public static void go() {} }' },
      { name: 'B', body: 'public without sharing class B { @AuraEnabled public static void go() {} }' },
    ]);
    expect(exposed(r)?.riskLevel).toBe('CRITICAL');
  });
});

describe('RULE-070 potential attack chains do not set the grade', () => {
  it('a potential CRITICAL chain alone does not force an F', () => {
    const r = buildAuditResult(ctx(), [f('LOW', 'p', { passed: true })], {}, undefined, [chain('CRITICAL', 'potential')]);
    expect(r.grade).not.toBe('F');
    expect(r.attackChains).toHaveLength(1);
  });

  it('a named CRITICAL chain still does', () => {
    const r = buildAuditResult(ctx(), [f('LOW', 'p', { passed: true })], {}, undefined, [chain('CRITICAL', 'named')]);
    expect(r.grade).toBe('F');
  });
});

describe('RULE-071 / RULE-072 attack chains need a connected path (INT-012, MN-056)', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const engine = async () => new (await import('../../../src/chains/ChainEngine.js')).ChainEngine();
  const ids = async (findingIds: string[]) =>
    (await engine()).correlate(findingIds.map((id) => f('HIGH', id))).filter((c) => c.confidence === 'named').map((c) => c.id);

  // The shapes seen on the three audited orgs: a guest user exists, plus internal weaknesses.
  it('RULE-071: a guest user and a classic site, plus system-context flows and Apex, is no exfiltration path', async () => {
    expect(
      await ids(['guest-user-baseline', 'classic-sites-active', 'flows-autolaunched-without-sharing', 'flows-screen-without-sharing',
        'portal-exposed-apex-without-sharing', 'field-level-security-high']),
    ).not.toContain('unauth-bulk-exfil');
  });

  it('RULE-071: a confirmed guest exposure opens it, and the surfaces join as steps', async () => {
    const chains = (await engine()).correlate(
      ['guest-object-exposure-public-owd', 'guest-user-baseline', 'classic-sites-active'].map((id) => f('HIGH', id)),
    );
    const chain = chains.find((c) => c.id === 'unauth-bulk-exfil');
    expect(chain?.steps.map((s) => s.findingId)).toEqual(
      expect.arrayContaining(['guest-object-exposure-public-owd', 'guest-user-baseline', 'classic-sites-active']),
    );
  });

  it('RULE-072: a guest user and admins holding admin permissions is no takeover path', async () => {
    expect(await ids(['guest-user-baseline', 'users-super-admin-combo', 'users-author-apex'])).not.toContain('standard-to-takeover');
  });

  it('RULE-072: a guest user and a non-admin escalation still needs a low-trust entry', async () => {
    expect(await ids(['guest-user-baseline', 'privileged-access-shadow-admins'])).not.toContain('standard-to-takeover');
  });

  it('RULE-072: a low-trust entry with a non-admin escalation fires, carrying admin findings as evidence', async () => {
    const chains = (await engine()).correlate(
      ['experience-cloud-site-self-registration', 'escalation-perms-found', 'users-super-admin-combo'].map((id) => f('HIGH', id)),
    );
    const chain = chains.find((c) => c.id === 'standard-to-takeover');
    expect(chain?.steps.map((s) => s.findingId)).toEqual(
      expect.arrayContaining(['experience-cloud-site-self-registration', 'escalation-perms-found', 'users-super-admin-combo']),
    );
  });

  it('RULE-072: admin evidence alone, with an entry but no non-admin escalation, does not fire', async () => {
    expect(await ids(['sharing-model-external-read', 'users-super-admin-combo', 'users-author-apex'])).not.toContain('standard-to-takeover');
  });
});

describe('RULE-075 separation of duties is rated on users the super-admin finding does not cover (MN-052)', () => {
  const grant = (id: string, perms: string[]) => ({ userId: id, username: `${id}@x.com`, name: id, profileName: 'P', perms });
  const ADMIN = ['ModifyAllData', 'ViewAllData', 'ManageUsers', 'AssignPermissionSets', 'AuthorApex'];
  const run = async (grants: unknown[]) => {
    const { SeparationOfDutiesCheck } = await import('../../../src/checks/impl/SeparationOfDutiesCheck.js');
    return new SeparationOfDutiesCheck().run(ctx({ cache: { effectivePermissions: grants } as any }));
  };

  it('super-admins alone produce no toxic-combination finding', async () => {
    const r = await run([grant('a', ADMIN), grant('b', ADMIN)]);
    expect(r.findings.map((x) => x.id)).toEqual(['separation-of-duties-ok']);
    expect(r.findings[0].passed).toBe(true);
    expect(r.findings[0].detail).toMatch(/super-admin/i);
  });

  it('a non-admin holding a combination is still flagged, and the left-out admins are named as a count', async () => {
    const r = await run([grant('a', ADMIN), grant('n', ['ManageUsers', 'AssignPermissionSets'])]);
    const x = r.findings.find((y) => y.id === 'separation-of-duties-self-escalation')!;
    expect(x.affectedItems!.map((i) => i.label)).toEqual(['n@x.com']);
    expect(x.title).toMatch(/^1 user/);
    expect(x.detail).toMatch(/1 super-admin/);
  });
});

describe('RULE-071 (potential chains) no potential path starts from a surface alone', () => {
  it('a guest user and a live site, with write-capable findings, produce no potential chain', async () => {
    const { ChainEngine } = await import('../../../src/chains/ChainEngine.js');
    const chains = new ChainEngine().correlate(
      ['guest-user-baseline', 'classic-sites-active', 'flows-autolaunched-without-sharing', 'users-modify-all-data'].map((id) => f('HIGH', id)),
    );
    expect(chains.filter((c) => c.confidence === 'potential' && c.id.startsWith('potential-unauth-foothold'))).toEqual([]);
  });
});

describe('RULE-076 the super-admin finding is graded on how many hold it (MN-052)', () => {
  const row = (id: string) => ({
    Assignee: { Id: id, Username: `${id}@x.com`, Name: id, Profile: { Name: 'System Administrator' } },
    PermissionSet: { Name: 'PS', IsOwnedByProfile: false, PermissionsModifyAllData: true, PermissionsViewAllData: true,
      PermissionsManageUsers: true, PermissionsCustomizeApplication: false, PermissionsAuthorApex: false },
  });
  const sev = async (n: number, isSandbox = false) => {
    const rows = Array.from({ length: n }, (_, i) => row(`u${i}`));
    const r = await new UsersAndAdminsCheck().run(
      ctx({ soql: { queryAll: (jest.fn() as any).mockResolvedValue(rows), query: (jest.fn() as any).mockImplementation((s: string) => Promise.resolve({ totalSize: /PermissionSetAssignment/.test(s) ? rows.length : 50, records: [] })) } as any }, isSandbox),
    );
    return r.findings.find((x) => x.id === 'users-super-admin-combo')?.riskLevel;
  };
  it.each([[1, 'LOW'], [3, 'LOW'], [4, 'HIGH'], [5, 'HIGH'], [6, 'CRITICAL']])('%i holder(s): %s', async (n, level) => {
    expect(await sev(n)).toBe(level);
  });
  it('the sandbox cap still applies', async () => expect(await sev(9, true)).toBe('HIGH'));
});

describe('RULE-077 escalation permissions are rated on users the super-admin finding does not cover', () => {
  const psa = (id: string, ps: Record<string, boolean>) => ({ AssigneeId: id, Assignee: { Username: `${id}@x.com` }, PermissionSet: ps });
  const run = async (escalationRows: unknown[], superRows: unknown[]) => {
    const { EscalationPermsCheck } = await import('../../../src/checks/impl/EscalationPermsCheck.js');
    const fields = ['PermissionsManageInternalUsers', 'PermissionsAssignPermissionSets', 'PermissionsModifyMetadata', 'PermissionsViewAllUsers',
      'PermissionsModifyAllData', 'PermissionsViewAllData', 'PermissionsManageUsers'];
    return new EscalationPermsCheck().run(
      ctx({
        rest: { get: async () => ({ fields: fields.map((name) => ({ name })) }) } as any,
        soql: { query: jest.fn(), queryAll: (jest.fn() as any).mockImplementation((q: string) => Promise.resolve(/PermissionsModifyAllData = true/.test(q) ? superRows : escalationRows)) } as any,
      }),
    );
  };
  const SUPER = { PermissionsModifyAllData: true, PermissionsViewAllData: true, PermissionsManageUsers: true };

  it('super-admins alone holding escalation permissions pass', async () => {
    const r = await run([psa('a', { PermissionsModifyMetadata: true })], [psa('a', SUPER)]);
    expect(r.findings[0].id).toBe('escalation-perms-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('a non-admin holder is flagged; super-admins are counted, not listed', async () => {
    const r = await run([psa('a', { PermissionsModifyMetadata: true }), psa('n', { PermissionsAssignPermissionSets: true })], [psa('a', SUPER)]);
    const f = r.findings.find((x) => x.id === 'escalation-perms-found')!;
    expect(f.affectedItems!.map((i) => i.label)).toEqual(['n@x.com: Assign Permission Sets']);
    expect(f.detail).toMatch(/1 super-admin/);
  });

  it('Password Never Expires and View All Users are hygiene, not escalation, and open no chain', async () => {
    const r = await run([psa('n', { PermissionsViewAllUsers: true })], []);
    expect(r.findings.map((x) => x.id)).toEqual(['escalation-perms-hygiene']);
    expect(r.findings[0].riskLevel).toBe('MEDIUM');
    const { ChainEngine } = await import('../../../src/chains/ChainEngine.js');
    const ids = new ChainEngine().correlate([f('HIGH', 'auth-providers-social'), r.findings[0]]).map((c) => c.id);
    expect(ids).not.toContain('standard-to-takeover');
  });

  it('login-as for administrators is evidence, not the escalation, in the takeover chain', async () => {
    const { ChainEngine } = await import('../../../src/chains/ChainEngine.js');
    const ids = new ChainEngine().correlate(['auth-providers-social', 'login-access-policy-login-as-enabled'].map((id) => f('HIGH', id))).map((c) => c.id);
    expect(ids).not.toContain('standard-to-takeover');
  });
});

describe('RULE-078 a defence-in-depth gap is at most MEDIUM', () => {
  it('the sandbox note appears only when the cap applied', async () => {
    const { UsersAndAdminsCheck: C } = await import('../../../src/checks/impl/UsersAndAdminsCheck.js');
    const row = (id: string) => ({ Assignee: { Id: id, Username: id, Name: id, Profile: { Name: 'SA' } },
      PermissionSet: { Name: 'PS', IsOwnedByProfile: false, PermissionsModifyAllData: true, PermissionsViewAllData: true, PermissionsManageUsers: true, PermissionsCustomizeApplication: false, PermissionsAuthorApex: false } });
    const rows = [row('a')];
    const r = await new C().run(ctx({ soql: { queryAll: (jest.fn() as any).mockResolvedValue(rows), query: (jest.fn() as any).mockImplementation((s: string) => Promise.resolve({ totalSize: /PermissionSetAssignment/.test(s) ? rows.length : 5, records: [] })) } as any }, true));
    expect(r.findings.find((x) => x.id === 'users-super-admin-combo')!.detail).not.toMatch(/sandbox/i);
  });
});

describe('RULE-079 the HTML dashboard counts the findings the grade counts (MN-055)', () => {
  const findings = [
    f('LOW', 'open-low'),
    f('LOW', 'passed-low', { passed: true }),
    f('LOW', 'blind-low', { inconclusive: true }),
    f('LOW', 'waived-low', { waived: true }),
    f('HIGH', 'open-high'),
    f('HIGH', 'passed-high', { passed: true }),
  ];
  const html = new HtmlRenderer().render(buildAuditResult(ctx(), findings, {}));
  const kpi = (level: string) =>
    new RegExp(`<div class="kpi-value"[^>]*>(\\d+)</div>\\s*<div class="kpi-label">${level}</div>`).exec(html)?.[1];

  it('KPI cards leave out passed, inconclusive and waived findings', () => {
    expect(kpi('LOW')).toBe('1');
    expect(kpi('HIGH')).toBe('1');
  });

  it('the donut total is the open-finding total', () => {
    expect(html).toMatch(/>2<\/text>\s*<text[^>]*>open findings</);
  });

  it('the grade reason sits below the gauge, not beside it', () => {
    expect(html).toMatch(/\.dash-score-panel \{ flex-direction: column;/);
  });
});
