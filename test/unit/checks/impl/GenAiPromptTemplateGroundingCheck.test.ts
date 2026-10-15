import { jest } from '@jest/globals';
import { GenAiPromptTemplateGroundingCheck } from '../../../../src/checks/impl/GenAiPromptTemplateGroundingCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

// Mocks answer only what the real calls return. The GenAiPromptTemplate Tooling row carries no
// body; the body, inputs and data providers come solely from metadata.read. Flow API names come
// from FlowDefinitionView (standard API) and run modes from the Tooling Flow version list.
interface Fixture {
  templates?: unknown[] | Error;
  metadata?: Record<string, unknown> | null; // keyed by DeveloperName; null = no Metadata client
  metadataError?: Error;
  flows?: Array<{ apiName: string; versionId: string; runInMode: string }>;
  apex?: Array<{ Name: string; Body: string }>;
}

function makeCtx(fx: Fixture): AuditContext {
  const flows = fx.flows ?? [];
  return {
    soql: {
      queryAll: (jest.fn() as any).mockImplementation((q: string) =>
        Promise.resolve(
          q.includes('FROM FlowDefinitionView')
            ? flows.map((f) => ({ ApiName: f.apiName, IsActive: true, ActiveVersionId: f.versionId, LatestVersionId: f.versionId }))
            : [],
        ),
      ),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation((q: string) => {
        if (q.includes('FROM GenAiPromptTemplate')) {
          const t = fx.templates ?? [];
          return t instanceof Error ? Promise.reject(t) : Promise.resolve(t);
        }
        if (q.includes('FROM Flow')) {
          return Promise.resolve(
            flows.map((f) => ({ Id: f.versionId, MasterLabel: f.apiName, ProcessType: 'AutoLaunchedFlow', Status: 'Active', RunInMode: f.runInMode })),
          );
        }
        if (q.includes('FROM ApexClass')) {
          const wanted = [...q.matchAll(/'([^']+)'/g)].map((m) => m[1].toLowerCase());
          return Promise.resolve((fx.apex ?? []).filter((c) => wanted.includes(c.Name.toLowerCase())));
        }
        return Promise.resolve([]);
      }),
    } as any,
    metadata:
      fx.metadata === null
        ? undefined
        : ({
            read: (jest.fn() as any).mockImplementation((_type: string, name: string) =>
              fx.metadataError ? Promise.reject(fx.metadataError) : Promise.resolve(fx.metadata?.[name] ?? null),
            ),
          } as any),
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

const tpl = (name: string) => ({ Id: `0hf${name}`, DeveloperName: name, MasterLabel: name });
const body = (content: string, providers: string[] = []) => ({
  templateVersions: [{ content, templateDataProviders: providers.map((definition) => ({ definition })) }],
});

describe('GenAiPromptTemplateGroundingCheck', () => {
  const check = new GenAiPromptTemplateGroundingCheck();

  it('passes when GenAiPromptTemplate is not enabled (sObject not supported)', async () => {
    const ctx = makeCtx({ templates: new Error("sObject type 'GenAiPromptTemplate' is not supported.") });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['genai-prompt-template-grounding-not-enabled']);
  });

  it('propagates a permission error on the template list instead of passing', async () => {
    const ctx = makeCtx({ templates: new Error('INSUFFICIENT_ACCESS: GenAiPromptTemplate') });
    await expect(check.run(ctx)).rejects.toThrow('INSUFFICIENT_ACCESS');
  });

  it('reads the template body from metadata and flags untrusted input beside CRM data', async () => {
    const ctx = makeCtx({
      templates: [tpl('Case_Reply')],
      metadata: { Case_Reply: body('Reply to {!$Input:Case.Description} for {!$Input:Account.Name}') },
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['genai-prompt-template-grounding-untrusted']);
  });

  it('flags a template grounded on a flow that runs in system mode without sharing', async () => {
    const ctx = makeCtx({
      templates: [tpl('Summary')],
      metadata: { Summary: body('Summarise', ['flow://Get_Account_Data']) },
      flows: [{ apiName: 'Get_Account_Data', versionId: '301000000000001AAA', runInMode: 'SystemModeWithoutSharing' }],
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['genai-prompt-template-grounding-flow']);
  });

  it('does not flag flows in DefaultMode or SystemModeWithSharing', async () => {
    const ctx = makeCtx({
      templates: [tpl('A'), tpl('B')],
      metadata: { A: body('{!$Flow:Default_Flow.Prompt}'), B: body('x', ['flow://Shared_Flow']) },
      flows: [
        { apiName: 'Default_Flow', versionId: '301000000000002AAA', runInMode: 'DefaultMode' },
        { apiName: 'Shared_Flow', versionId: '301000000000003AAA', runInMode: 'SystemModeWithSharing' },
      ],
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['genai-prompt-template-grounding-ok']);
  });

  it('does not tie a template to a flow whose name it merely mentions', async () => {
    const ctx = makeCtx({
      templates: [tpl('Case_Note')],
      metadata: { Case_Note: body('Write a note about this Case') },
      flows: [{ apiName: 'Case', versionId: '301000000000004AAA', runInMode: 'SystemModeWithoutSharing' }],
    });
    const r = await check.run(ctx);
    expect(r.findings.map((f) => f.id)).toEqual(['genai-prompt-template-grounding-ok']);
  });

  it('flags grounding on Apex declared without sharing, and not on a with-sharing class', async () => {
    const ctx = makeCtx({
      templates: [tpl('Risky'), tpl('Safe')],
      metadata: { Risky: body('{!$Apex:LeakyGrounder.Prompt}'), Safe: body('x', ['apex://SafeGrounder']) },
      apex: [
        { Name: 'LeakyGrounder', Body: 'public without sharing class LeakyGrounder { }' },
        { Name: 'SafeGrounder', Body: 'public with sharing class SafeGrounder { // without sharing elsewhere\n }' },
      ],
    });
    const r = await check.run(ctx);
    const f = r.findings.find((x) => x.id === 'genai-prompt-template-grounding-apex');
    expect(f?.affectedItems?.map((i) => i.label)).toEqual(['Risky']);
  });

  it('is inconclusive, not passed, when template metadata cannot be read', async () => {
    const ctx = makeCtx({ templates: [tpl('X')], metadataError: new Error('INSUFFICIENT_ACCESS') });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.passed)).toBe(false);
    expect(r.findings[0].id).toBe('genai-prompt-template-grounding-inconclusive');
  });

  it('is inconclusive, not passed, when there is no Metadata client', async () => {
    const ctx = makeCtx({ templates: [tpl('X')], metadata: null });
    const r = await check.run(ctx);
    expect(r.findings.some((f) => f.passed)).toBe(false);
    expect(r.findings[0].inconclusive).toBe(true);
  });
});
