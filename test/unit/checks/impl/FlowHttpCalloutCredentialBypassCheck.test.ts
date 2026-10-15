import { jest } from '@jest/globals';
import { FlowHttpCalloutCredentialBypassCheck } from '../../../../src/checks/impl/FlowHttpCalloutCredentialBypassCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(toolingData: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(toolingData)) {
          if (q.includes(key)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
        }
        return Promise.resolve([]);
      }),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: '00D000000000001',
      name: 'Test Org',
      type: 'Developer Edition',
      isSandbox: false,
      instance: 'NA1',
      instanceUrl: 'https://test.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

describe('FlowHttpCalloutCredentialBypassCheck', () => {
  const check = new FlowHttpCalloutCredentialBypassCheck();

  it('passes when no flows have secrets and external services have Named Credentials', async () => {
    const ctx = makeCtx({
      ExternalServiceRegistration: [
        { Id: '0es1', DeveloperName: 'PaymentService', MasterLabel: 'Payment Service', NamedCredentialId: '0nc1' },
      ],
      Flow: [
        { Id: '301', DeveloperName: 'CleanFlow', MasterLabel: 'Clean Flow', ProcessType: 'Flow' },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('flow-http-callout-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags flows containing hardcoded secrets in description or metadata', async () => {
    const ctx = makeCtx({
      ExternalServiceRegistration: [],
      Flow: [
        {
          Id: '302',
          DeveloperName: 'WebhookFlow',
          MasterLabel: 'Webhook Flow',
          ProcessType: 'Flow',
          Metadata: {
            formulas: [{ name: 'AuthHeader', expression: '"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"' }],
          },
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'flow-http-callout-hardcoded-secret');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('flags ExternalServiceRegistration missing a Named Credential', async () => {
    const ctx = makeCtx({
      ExternalServiceRegistration: [
        { Id: '0es2', DeveloperName: 'LegacyService', MasterLabel: 'Legacy Service', NamedCredentialId: null },
      ],
      Flow: [],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'flow-http-callout-uncredentialed-endpoint');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });
});
