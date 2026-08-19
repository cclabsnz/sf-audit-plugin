import { jest } from '@jest/globals';
import { CertificateExpiryCheck } from '../../../../src/checks/impl/CertificateExpiryCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(certs: unknown[] | Error): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() =>
        certs instanceof Error ? Promise.reject(certs) : Promise.resolve(certs),
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

const DAY = 86_400_000;

/**
 * A certificate expiring `days` from now. Dates are computed relative to the moment the test
 * runs, because the check reads Date.now() — a fixed date would rot.
 */
const cert = (label: string, days: number | null) => ({
  Id: `0PE${label}`,
  MasterLabel: label,
  DeveloperName: label.replace(/\W/g, '_'),
  ExpirationDate: days === null ? null : new Date(Date.now() + days * DAY).toISOString(),
});

describe('CertificateExpiryCheck', () => {
  const check = new CertificateExpiryCheck();

  it('is inconclusive when the Certificate object is unreadable', async () => {
    const r = await check.run(makeCtx(new Error('INSUFFICIENT_ACCESS')));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('certificate-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('reports an INFO finding, not a pass, when the org has no certificates', async () => {
    const r = await check.run(makeCtx([]));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('certificate-none');
    expect(r.findings[0].riskLevel).toBe('INFO');
    // No certificates is an absence of evidence, not a healthy result.
    expect(r.findings[0].passed).toBeUndefined();
  });

  it('passes when every certificate has more than 180 days left', async () => {
    const r = await check.run(makeCtx([cert('Prod', 200), cert('Backup', 365)]));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('certificate-ok');
    expect(r.findings[0].passed).toBe(true);
    expect(r.findings[0].title).toContain('2 certificate(s)');
  });

  // The three thresholds, tested either side of each boundary.
  it.each([
    [10, 'certificate-expiring-critical', 'CRITICAL'],
    [30, 'certificate-expiring-critical', 'CRITICAL'],
    [45, 'certificate-expiring-soon', 'HIGH'],
    [90, 'certificate-expiring-soon', 'HIGH'],
    [120, 'certificate-expiring-medium', 'MEDIUM'],
    [179, 'certificate-expiring-medium', 'MEDIUM'],
  ])('a certificate %i days out is %s (%s)', async (days, id, severity) => {
    const r = await check.run(makeCtx([cert('C', days)]));
    const f = r.findings.find((x) => x.id === id);
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe(severity);
    // It must land in exactly one bucket.
    expect(r.findings).toHaveLength(1);
  });

  it('treats an already-expired certificate as CRITICAL', async () => {
    const r = await check.run(makeCtx([cert('Lapsed', -30)]));
    const f = r.findings.find((x) => x.id === 'certificate-expiring-critical');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    // The note carries the negative day count, so an expired cert reads as expired.
    expect(f!.affectedItems?.[0].note).toMatch(/-?\d+ day\(s\)/);
  });

  it('separates certificates into all three buckets in one run', async () => {
    const r = await check.run(makeCtx([
      cert('Urgent', 5), cert('Soon', 60), cert('Later', 150), cert('Fine', 400),
    ]));
    const ids = r.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining([
      'certificate-expiring-critical', 'certificate-expiring-soon', 'certificate-expiring-medium',
    ]));
    // The healthy one does not produce a pass finding alongside real problems.
    expect(ids).not.toContain('certificate-ok');
    for (const id of ids) {
      expect(r.findings.find((f) => f.id === id)!.affectedItems).toHaveLength(1);
    }
  });

  it('includes the expiry date in the note so it can be acted on without the org', async () => {
    const r = await check.run(makeCtx([cert('Prod', 10)]));
    const note = r.findings[0].affectedItems?.[0].note!;
    expect(note).toMatch(/expires \d{4}-\d{2}-\d{2}/);
  });

  /**
   * A certificate with no ExpirationDate is skipped by the bucketing loop. If it is the only
   * certificate, the check reports `certificate-ok` — "All 1 certificate(s) are healthy" — for a
   * certificate whose expiry is unknown. Pinned as current behaviour; worth revisiting, since
   * "we could not tell" and "it is fine" are different answers.
   */
  it('currently reports a null expiry date as healthy', async () => {
    const r = await check.run(makeCtx([cert('Unknown', null)]));
    expect(r.findings[0].id).toBe('certificate-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('ignores a null-expiry certificate without hiding a real one', async () => {
    const r = await check.run(makeCtx([cert('Unknown', null), cert('Urgent', 5)]));
    expect(r.findings.some((f) => f.id === 'certificate-expiring-critical')).toBe(true);
    expect(r.findings.find((f) => f.id === 'certificate-expiring-critical')!.affectedItems)
      .toHaveLength(1);
  });
});
