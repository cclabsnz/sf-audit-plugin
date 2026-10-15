import { jest } from '@jest/globals';
import { GenAiPromptTemplateGroundingCheck } from '../../../../src/checks/impl/GenAiPromptTemplateGroundingCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(toolingResponses: Record<string, unknown[] | Error>): AuditContext {
  return {
    soql: {} as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        for (const [key, res] of Object.entries(toolingResponses)) {
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

describe('GenAiPromptTemplateGroundingCheck', () => {
  const check = new GenAiPromptTemplateGroundingCheck();

  it('passes when GenAiPromptTemplate is not enabled (sObject not supported)', async () => {
    const err = new Error("sObject type 'GenAiPromptTemplate' is not supported.");
    const ctx = makeCtx({ GenAiPromptTemplate: err });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('genai-prompt-template-grounding-not-enabled');
    expect(r.findings[0].passed).toBe(true);
  });

  it('marks inconclusive on generic tooling query error', async () => {
    const ctx = makeCtx({ GenAiPromptTemplate: new Error('UNEXPECTED_EXCEPTION') });
    const r = await check.run(ctx);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].id).toBe('genai-prompt-template-grounding-inaccessible');
    expect(r.findings[0].inconclusive).toBe(true);
  });

  it('passes when no templates are found', async () => {
    const ctx = makeCtx({ GenAiPromptTemplate: [] });
    const r = await check.run(ctx);
    expect(r.findings[0].id).toBe('genai-prompt-template-grounding-ok');
    expect(r.findings[0].passed).toBe(true);
  });

  it('flags template grounded on system-mode flow and unshared apex', async () => {
    const ctx = makeCtx({
      GenAiPromptTemplate: [
        {
          Id: '001',
          DeveloperName: 'Support_Prompt',
          MasterLabel: 'Support Prompt',
          TemplateType: 'einstein_gpt__flex',
          Description: 'Grounding via Flow: Flow_GetRecords and Apex: PromptGroundingClass',
        },
      ],
      Flow: [
        {
          Id: '301',
          DeveloperName: 'Flow_GetRecords',
          MasterLabel: 'Flow GetRecords',
          ProcessType: 'PromptFlow',
          RunInMode: 'SystemModeWithoutSharing',
        },
      ],
      ApexClass: [
        {
          Id: '01p1',
          Name: 'PromptGroundingClass',
          Body: 'public without sharing class PromptGroundingClass { @InvocableMethod public static void run() {} }',
        },
      ],
    });

    const r = await check.run(ctx);
    const flowFinding = r.findings.find((f) => f.id === 'genai-prompt-template-grounding-flow');
    expect(flowFinding).toBeDefined();
    expect(flowFinding?.riskLevel).toBe('HIGH');

    const apexFinding = r.findings.find((f) => f.id === 'genai-prompt-template-grounding-apex');
    expect(apexFinding).toBeDefined();
    expect(apexFinding?.riskLevel).toBe('HIGH');
  });

  it('flags untrusted field interpolation alongside privileged CRM data', async () => {
    const ctx = makeCtx({
      GenAiPromptTemplate: [
        {
          Id: '001',
          DeveloperName: 'Case_Summary',
          MasterLabel: 'Case Summary',
          Description: 'Customer said {!Case.Description}. User details: {!User.Name} {!Account.Name}',
        },
      ],
    });

    const r = await check.run(ctx);
    const untrustedFinding = r.findings.find((f) => f.id === 'genai-prompt-template-grounding-untrusted');
    expect(untrustedFinding).toBeDefined();
    expect(untrustedFinding?.riskLevel).toBe('HIGH');
  });
});
