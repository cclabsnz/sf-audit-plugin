import { jest } from '@jest/globals';
import { InboundEmailHandlerExposureCheck } from '../../../../src/checks/impl/InboundEmailHandlerExposureCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(soqlResponses: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(soqlResponses)) {
          if (q.includes(key)) {
            return res instanceof Error ? Promise.reject(res) : Promise.resolve(res);
          }
        }
        return Promise.resolve([]);
      }),
    } as any,
    tooling: {} as any,
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

describe('InboundEmailHandlerExposureCheck', () => {
  const check = new InboundEmailHandlerExposureCheck();

  it('passes when no active email services functions exist', async () => {
    const ctx = makeCtx({ EmailServicesFunction: [] });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('inbound-email-handler-exposure-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags inbound email service allowing open unauthenticated execution as admin', async () => {
    const ctx = makeCtx({
      EmailServicesFunction: [
        {
          Id: '01u1',
          FunctionName: 'SupportEmailHandler',
          IsActive: true,
          RunAsUserId: '005Admin',
          ApexClassId: '01pClass',
          AuthenticationFailureAction: '0',
        },
      ],
      EmailServicesAddress: [
        {
          Id: '01v1',
          FunctionId: '01u1',
          LocalPart: 'support',
          EmailDomainName: 'salesforce.com',
          IsActive: true,
          AuthorizedSenders: '',
        },
      ],
      User: [
        {
          Id: '005Admin',
          Username: 'admin@corp.com',
          Profile: { Name: 'System Administrator' },
        },
      ],
      ApexClass: [
        {
          Id: '01pClass',
          Name: 'SupportEmailHandler',
          Body: 'global without sharing class SupportEmailHandler implements Messaging.InboundEmailHandler { insert new Case(); }',
        },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'inbound-email-handler-unauthenticated-execution');
    expect(f).toBeDefined();
    expect(f?.riskLevel).toBe('HIGH');
  });

  it('passes when email service enforces authorized senders', async () => {
    const ctx = makeCtx({
      EmailServicesFunction: [
        {
          Id: '01u2',
          FunctionName: 'SecureEmailHandler',
          IsActive: true,
          RunAsUserId: '005Standard',
          ApexClassId: '01pClass2',
          AuthenticationFailureAction: '2',
        },
      ],
      EmailServicesAddress: [
        {
          Id: '01v2',
          FunctionId: '01u2',
          LocalPart: 'billing',
          EmailDomainName: 'salesforce.com',
          IsActive: true,
          AuthorizedSenders: 'partner@trustedcorp.com',
        },
      ],
      User: [
        {
          Id: '005Standard',
          Username: 'std@corp.com',
          Profile: { Name: 'Standard User' },
        },
      ],
      ApexClass: [
        {
          Id: '01pClass2',
          Name: 'SecureEmailHandler',
          Body: 'public with sharing class SecureEmailHandler {}',
        },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('inbound-email-handler-exposure-ok');
    expect(r.findings[0].passed).toBe(true);
  });
});
