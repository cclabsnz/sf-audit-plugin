import { SessionHardeningCheck } from '../../../../src/checks/impl/SessionHardeningCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(healthCheckRisks: unknown, sessionSettings?: Record<string, unknown>): AuditContext {
  const metadata = sessionSettings ? { read: (async () => ({ sessionSettings })) as any } : undefined;
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    metadata,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: healthCheckRisks === undefined ? {} : { healthCheckRisks },
  } as any;
}

describe('SessionHardeningCheck', () => {
  const check = new SessionHardeningCheck();

  it('is inconclusive when health check risks were never collected', async () => {
    const r = await check.run(makeCtx(undefined));
    expect(r.findings[0].id).toBe('session-hardening-inconclusive');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('passes when no session/clickjack settings are flagged', async () => {
    const r = await check.run(makeCtx([{ setting: 'Minimum password length', riskType: 'MEDIUM_RISK', value: '5', score: 4 }]));
    expect(r.findings.some((f) => f.id === 'session-hardening-ok' && f.passed)).toBe(true);
  });

  it('flags matching settings as HIGH when a high-risk one is present', async () => {
    const r = await check.run(
      makeCtx([
        { setting: 'Clickjack protection level', riskType: 'HIGH_RISK', value: 'off', score: 10 },
        { setting: 'Enable CSRF protection on GET requests', riskType: 'MEDIUM_RISK', value: 'off', score: 4 },
      ]),
    );
    const f = r.findings.find((x) => x.id === 'session-hardening-risks');
    expect(f?.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.length).toBe(2);
  });

  it('flags as MEDIUM when only medium-risk session settings deviate', async () => {
    const r = await check.run(makeCtx([{ setting: 'Lock sessions to the IP address', riskType: 'MEDIUM_RISK', value: 'off', score: 4 }]));
    expect(r.findings.find((x) => x.id === 'session-hardening-risks')?.riskLevel).toBe('MEDIUM');
  });

  it('prefers authoritative SecuritySettings metadata: flags disabled clickjack as HIGH', async () => {
    const r = await check.run(
      makeCtx(undefined, {
        enableClickjackNonsetupUser: false,
        enableClickjackNonsetupSFDC: true,
        enableXssProtection: true,
        enableCSRFOnGet: true,
        enableCSRFOnPost: true,
        enableContentSniffingProtection: true,
      }),
    );
    const f = r.findings.find((x) => x.id === 'session-hardening-risks');
    expect(f?.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].label).toMatch(/Clickjack/);
  });

  it('passes from metadata when all protections are enabled', async () => {
    const r = await check.run(
      makeCtx(undefined, {
        enableClickjackNonsetupUser: true,
        enableClickjackNonsetupSFDC: true,
        enableXssProtection: true,
        enableCSRFOnGet: true,
        enableCSRFOnPost: true,
        enableContentSniffingProtection: true,
      }),
    );
    expect(r.findings.some((f) => f.id === 'session-hardening-ok' && f.passed)).toBe(true);
  });
});
