import { jest } from '@jest/globals';
import { FlowHttpCalloutCredentialBypassCheck } from '../../../../src/checks/impl/FlowHttpCalloutCredentialBypassCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

// Mocks answer only what the real queries return: FlowDefinitionView rows carry no metadata,
// and Flow.Metadata comes back solely from a one-row `WHERE Id = '...'` Tooling query.
interface FlowFixture {
  apiName: string;
  versionId: string;
  metadata?: unknown;
  readError?: Error;
}

function makeCtx(opts: {
  flows?: FlowFixture[];
  services?: unknown[] | Error;
  definitionsError?: Error;
}): AuditContext {
  const flows = opts.flows ?? [];
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        if (!q.includes('FROM FlowDefinitionView')) return Promise.resolve([]);
        if (opts.definitionsError) return Promise.reject(opts.definitionsError);
        return Promise.resolve(
          flows.map((f) => ({ ApiName: f.apiName, IsActive: true, ActiveVersionId: f.versionId, LatestVersionId: f.versionId })),
        );
      }),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        if (q.includes('FROM ExternalServiceRegistration')) {
          const s = opts.services ?? [];
          return s instanceof Error ? Promise.reject(s) : Promise.resolve(s);
        }
        const byId = /FROM Flow WHERE Id = '([^']+)'/.exec(q);
        if (byId && q.includes('Metadata')) {
          const f = flows.find((x) => x.versionId === byId[1]);
          if (f?.readError) return Promise.reject(f.readError);
          return Promise.resolve(f ? [{ Id: f.versionId, Metadata: f.metadata ?? {} }] : []);
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

const id = (n: number) => `301000000000${String(n).padStart(3, '0')}AAA`;

describe('FlowHttpCalloutCredentialBypassCheck', () => {
  const check = new FlowHttpCalloutCredentialBypassCheck();

  it('passes when flows hold no secrets and every external service has a Named Credential', async () => {
    const ctx = makeCtx({
      services: [{ Id: '0es1', DeveloperName: 'Pay', MasterLabel: 'Pay', NamedCredential: 'PayCred', NamedCredentialReferenceId: null }],
      flows: [{ apiName: 'Clean_Flow', versionId: id(1), metadata: { formulas: [{ name: 'f', expression: 'TODAY()' }] } }],
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['flow-http-callout-ok']);
    expect(r.findings[0].passed).toBe(true);
  });

  it('finds a bearer token in an HTTP callout header formula', async () => {
    const ctx = makeCtx({
      flows: [
        {
          apiName: 'Sync_Orders',
          versionId: id(2),
          metadata: { formulas: [{ name: 'AuthHeader', expression: '"Bearer abcdef1234567890XYZ"' }] },
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'flow-http-callout-hardcoded-secret');
    expect(f?.affectedItems?.[0].label).toBe('Sync_Orders');
    expect(f?.affectedItems?.[0].url).toContain(id(2));
  });

  it('finds a secret in places beyond formulas, such as an action input or text template', async () => {
    const ctx = makeCtx({
      flows: [
        {
          apiName: 'Call_Api',
          versionId: id(3),
          metadata: {
            actionCalls: [{ inputParameters: [{ name: 'auth', value: { stringValue: "api_key = 'k3y-0123456789'" } }] }],
          },
        },
        {
          apiName: 'Template_Flow',
          versionId: id(4),
          metadata: { textTemplates: [{ text: 'https://svc:hunter2pass@api.example.com/x' }] },
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'flow-http-callout-hardcoded-secret');
    expect(f?.affectedItems?.map((i) => i.label)).toEqual(['Call_Api', 'Template_Flow']);
  });

  it('flags external services with no Named Credential', async () => {
    const ctx = makeCtx({
      services: [{ Id: '0es2', DeveloperName: 'Raw', MasterLabel: 'Raw Endpoint', NamedCredential: null, NamedCredentialReferenceId: null }],
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['flow-http-callout-uncredentialed-endpoint']);
  });

  it('counts a credential named only by reference as a Named Credential', async () => {
    const ctx = makeCtx({
      services: [{ Id: '0es3', DeveloperName: 'Ref', MasterLabel: 'Ref', NamedCredential: null, NamedCredentialReferenceId: '0XA9' }],
    });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.id === 'flow-http-callout-uncredentialed-endpoint')).toBe(false);
  });

  it('is inconclusive, not passed, when some flow metadata cannot be read', async () => {
    const ctx = makeCtx({
      flows: [
        { apiName: 'Readable', versionId: id(5), metadata: {} },
        { apiName: 'Locked', versionId: id(6), readError: new Error('INSUFFICIENT_ACCESS: no') },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.passed)).toBe(false);
    const f = r.findings.find((x) => x.id === 'flow-http-callout-inconclusive');
    expect(f?.inconclusive).toBe(true);
    expect(f?.title).toContain('1 of 2');
  });

  it('propagates a permission error on the flow listing so the engine reports it as inconclusive', async () => {
    const ctx = makeCtx({ definitionsError: new Error('INSUFFICIENT_ACCESS_OR_READONLY') });
    await expect(check.run(ctx)).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('propagates a permission error on ExternalServiceRegistration instead of passing', async () => {
    const ctx = makeCtx({ services: new Error('INSUFFICIENT_ACCESS: ExternalServiceRegistration') });
    await expect(check.run(ctx)).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('treats ExternalServiceRegistration being absent from the org as no services', async () => {
    const ctx = makeCtx({
      services: Object.assign(new Error("sObject type 'ExternalServiceRegistration' is not supported"), {
        errorCode: 'INVALID_TYPE',
      }),
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['flow-http-callout-ok']);
  });
});
