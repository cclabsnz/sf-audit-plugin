import { jest } from '@jest/globals';
import { DeploymentIdentityCheck } from '../../../../src/checks/impl/DeploymentIdentityCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(opts: {
  connectedAppNames?: string[];
  trail?: unknown[] | Error;
} = {}): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation(() =>
        opts.trail instanceof Error ? Promise.reject(opts.trail) : Promise.resolve(opts.trail ?? []),
      ),
      query: jest.fn(),
    } as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: { connectedAppNames: opts.connectedAppNames } as any,
  } as any;
}

const entry = (userId: string, profile = 'Standard User', daysAgo = 5) => ({
  CreatedDate: new Date(Date.now() - daysAgo * 86_400_000).toISOString(),
  CreatedBy: { Id: userId, Username: `${userId}@x.com`, Profile: { Name: profile } },
  Section: 'Change Sets', Action: 'deploy', Display: 'Deployed change set',
});

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('DeploymentIdentityCheck', () => {
  const check = new DeploymentIdentityCheck();

  it('declares its cache dependency', () => {
    expect(check.dependsOnCache).toEqual(expect.arrayContaining(['connectedAppNames']));
  });

  it('is inconclusive when the audit trail cannot be read', async () => {
    const r = await check.run(makeCtx({ trail: new Error('INSUFFICIENT_ACCESS') }));
    const f = find(r, 'deployment-audit-trail-inaccessible')!;
    expect(f.inconclusive).toBe(true);
    expect(f.riskLevel).toBe('MEDIUM');
    expect(f.passed).toBeUndefined();
  });

  it('reports INFO, not a pass, when there is no evidence either way', async () => {
    const r = await check.run(makeCtx({}));
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f.id).toBe('deployment-no-activity');
    expect(f.riskLevel).toBe('INFO');
    // Absence of audit entries is not proof of controlled deployment — JWT/Metadata API
    // deployments may not appear at all, and the detail says so.
    expect(f.passed).toBeUndefined();
    expect(f.detail).toContain('JWT');
  });

  // Signal 1: a CI/CD-named connected app suggests a pipeline exists.
  it.each(['Jenkins Deploy', 'GitHub Actions', 'Copado', 'Gearset', 'AutoRABIT', 'my-pipeline'])(
    'recognises %s as CI/CD tooling',
    async (name) => {
      const r = await check.run(makeCtx({ connectedAppNames: [name] }));
      const f = find(r, 'deployment-cicd-apps-found')!;
      expect(f.passed).toBe(true);
      expect(f.affectedItems?.[0].label).toBe(name);
    },
  );

  it('ignores unrelated connected app names', async () => {
    const r = await check.run(makeCtx({ connectedAppNames: ['Salesforce Mobile', 'Slack'] }));
    expect(find(r, 'deployment-cicd-apps-found')).toBeUndefined();
  });

  // Signal 2: SBS-DEP-001 wants one designated identity.
  it('passes when all deployment activity came from one identity', async () => {
    const r = await check.run(makeCtx({
      trail: [entry('svc_deploy'), entry('svc_deploy'), entry('svc_deploy')],
    }));
    const f = find(r, 'deployment-single-identity')!;
    expect(f.passed).toBe(true);
    expect(f.detail).toContain('svc_deploy@x.com');
    expect(f.detail).toContain('3 deployment-related');
  });

  it.each([
    [2, 'MEDIUM'], [3, 'MEDIUM'], [4, 'HIGH'], [6, 'HIGH'],
  ])('rates %i distinct deployers as %s', async (n, expected) => {
    const trail = Array.from({ length: n }, (_, i) => entry(`u${i}`));
    const r = await check.run(makeCtx({ trail }));
    const f = find(r, 'deployment-multiple-identities')!;
    expect(f.riskLevel).toBe(expected);
    expect(f.title).toContain(`${n} distinct user(s)`);
  });

  it('counts actions per user rather than treating each entry as a deployer', async () => {
    const r = await check.run(makeCtx({
      trail: [entry('a'), entry('a'), entry('a'), entry('b')],
    }));
    const f = find(r, 'deployment-multiple-identities')!;
    expect(f.title).toContain('2 distinct user(s)');
    const noteA = f.affectedItems!.find((i) => i.label === 'a@x.com')!.note!;
    expect(noteA).toContain('3 deployment action(s)');
  });

  // SBS-DEP-003: human admin accounts deploying is a monitoring gap, distinct from how many
  // identities are involved.
  it.each([
    ['System Administrator', true],
    ['Custom Admin Profile', true],
    ['Integration User', false],
    ['Standard User', false],
  ])('profile %s counts as an admin deployer: %s', async (profile, expected) => {
    const r = await check.run(makeCtx({ trail: [entry('u', profile)] }));
    expect(find(r, 'deployment-admin-accounts') !== undefined).toBe(expected);
  });

  it('reports the admin-deployer finding alongside the single-identity pass', async () => {
    const r = await check.run(makeCtx({ trail: [entry('boss', 'System Administrator')] }));
    // One identity satisfies SBS-DEP-001, but that identity being a human admin is still
    // an SBS-DEP-003 concern — the two are independent.
    expect(find(r, 'deployment-single-identity')!.passed).toBe(true);
    expect(find(r, 'deployment-admin-accounts')!.riskLevel).toBe('MEDIUM');
  });

  it('scopes the audit query to deployment sections and the last 90 days', async () => {
    const ctx = makeCtx({});
    await check.run(ctx);
    const q = (ctx.soql.queryAll as any).mock.calls[0][0] as string;
    expect(q).toMatch(/LAST_N_DAYS:90/);
    for (const section of ['Change Sets', 'Developer Tools', 'Packages', 'Metadata']) {
      expect(q).toContain(section);
    }
  });

  it('falls back to Unknown when the deployer profile is absent', async () => {
    const r = await check.run(makeCtx({
      trail: [{
        CreatedDate: new Date().toISOString(),
        CreatedBy: { Id: 'u', Username: 'u@x.com' },
        Section: 'Metadata', Action: 'deploy', Display: 'x',
      }],
    }));
    expect(find(r, 'deployment-single-identity')!.detail).toContain('Unknown');
  });

  it('still reports deployers when a CI/CD app is also present', async () => {
    const r = await check.run(makeCtx({
      connectedAppNames: ['Jenkins'],
      trail: [entry('a'), entry('b')],
    }));
    expect(find(r, 'deployment-cicd-apps-found')).toBeDefined();
    expect(find(r, 'deployment-multiple-identities')).toBeDefined();
  });
});
