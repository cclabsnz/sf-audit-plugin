import { SiemIntegrationCheck } from '../../../../src/checks/impl/SiemIntegrationCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

function makeCtx(cache: Record<string, unknown> = {}): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: { ...cache } as any,
  } as any;
}

const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('SiemIntegrationCheck', () => {
  const check = new SiemIntegrationCheck();

  it('reads every signal source from cache, adding no queries of its own', () => {
    expect(check.dependsOnCache).toEqual(expect.arrayContaining([
      'namedCredentialEndpoints', 'remoteSiteUrls', 'connectedAppNames',
      'scheduledApexClassNames', 'eventLogSummary',
    ]));
  });

  it('reports HIGH when no monitoring integration is detectable', async () => {
    const r = await check.run(makeCtx());
    expect(r.findings).toHaveLength(1);
    const f = r.findings[0];
    expect(f.id).toBe('siem-integration-not-detected');
    expect(f.riskLevel).toBe('HIGH');
    expect(f.passed).toBeUndefined();
  });

  it.each([
    ['https://http-inputs.splunkcloud.com/services', 'Splunk'],
    ['https://api.datadoghq.com/v1/input', 'Datadog'],
    ['https://collectors.sumologic.com/receiver', 'Sumo Logic'],
    ['https://my-cluster.elastic.co:9243', 'Elastic'],
    ['https://sentinel.azure-sentinel.io/ingest', 'Sentinel'],
  ])('detects %s as a SIEM endpoint (%s)', async (url) => {
    const r = await check.run(makeCtx({ namedCredentialEndpoints: [url] }));
    const f = find(r, 'siem-integration-detected')!;
    expect(f.passed).toBe(true);
    expect(f.affectedItems?.[0].note).toBe('Named Credential endpoint');
  });

  it.each([
    ['remoteSiteUrls', 'https://splunk.internal', 'Remote Site URL'],
    ['connectedAppNames', 'Datadog Integration', 'Connected App'],
    ['scheduledApexClassNames', 'LogForwardJob', 'Scheduled Apex class'],
  ])('detects a signal from %s', async (key, value, expectedNote) => {
    const r = await check.run(makeCtx({ [key]: [value] }));
    expect(find(r, 'siem-integration-detected')!.affectedItems?.[0].note).toBe(expectedNote);
  });

  it('ignores unrelated endpoints and app names', async () => {
    const r = await check.run(makeCtx({
      namedCredentialEndpoints: ['https://api.stripe.com'],
      connectedAppNames: ['Salesforce Mobile'],
      scheduledApexClassNames: ['NightlyBatch'],
    }));
    expect(r.findings[0].id).toBe('siem-integration-not-detected');
  });

  it('counts signals across all four sources', async () => {
    const r = await check.run(makeCtx({
      namedCredentialEndpoints: ['https://splunk.io'],
      remoteSiteUrls: ['https://datadoghq.com'],
      connectedAppNames: ['Sumo Export'],
      scheduledApexClassNames: ['SiemSync'],
    }));
    const f = find(r, 'siem-integration-detected')!;
    expect(f.title).toContain('4 SIEM/monitoring integration signal(s)');
    expect(f.affectedItems).toHaveLength(4);
    // The detail names each source group so the reader can verify the inference.
    for (const label of ['Named Credentials', 'Remote Sites', 'Connected Apps', 'Scheduled Apex']) {
      expect(f.detail).toContain(label);
    }
  });

  /**
   * The retention finding is deliberately conditional on there being no SIEM: if logs are
   * being shipped out, short native retention is not a gap.
   */
  describe('retention gap', () => {
    const shortLog = { totalFiles: 5, earliestDate: new Date(Date.now() - 7 * 86_400_000).toISOString() };

    it('flags short native retention when nothing is forwarding logs', async () => {
      const r = await check.run(makeCtx({ eventLogSummary: shortLog }));
      const f = find(r, 'siem-retention-gap')!;
      expect(f.riskLevel).toBe('MEDIUM');
      expect(f.title).toMatch(/\d+ day\(s\)/);
    });

    it('does not flag retention when a SIEM is already detected', async () => {
      const r = await check.run(makeCtx({
        eventLogSummary: shortLog,
        connectedAppNames: ['Splunk Forwarder'],
      }));
      expect(find(r, 'siem-retention-gap')).toBeUndefined();
    });

    it('does not flag retention when coverage already exceeds 30 days', async () => {
      const r = await check.run(makeCtx({
        eventLogSummary: { totalFiles: 5, earliestDate: new Date(Date.now() - 60 * 86_400_000).toISOString() },
      }));
      expect(find(r, 'siem-retention-gap')).toBeUndefined();
    });

    it('says nothing about retention when there are no event logs at all', async () => {
      const r = await check.run(makeCtx({ eventLogSummary: { totalFiles: 0, earliestDate: null } }));
      expect(find(r, 'siem-retention-gap')).toBeUndefined();
    });
  });
});
