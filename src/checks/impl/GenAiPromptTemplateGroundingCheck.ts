import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

interface GenAiPromptTemplateRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel: string;
  TemplateType?: string | null;
  TemplateContent?: string | null;
  Description?: string | null;
}

interface FlowRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel: string;
  ProcessType: string;
  RunInMode?: string | null;
}

interface ApexClassRecord {
  Id: string;
  Name: string;
  Body?: string | null;
}

function isMissingObjectError(err: unknown): boolean {
  if (isApiError(err)) {
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode)) return true;
    if (err.statusCode === 404) return true;
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes('is not supported') ||
    msg.includes('sobject type')
  );
}

// Untrusted external text inputs that may carry prompt injections into prompt templates
const UNTRUSTED_FIELD_PATTERNS = [
  /Lead\.Description/i,
  /Case\.SuppliedName/i,
  /Case\.Description/i,
  /EmailMessage\.TextBody/i,
  /EmailMessage\.HtmlBody/i,
];

// Privileged CRM fields that should not be colocated with untrusted external inputs in an unescaped prompt
const PRIVILEGED_DATA_PATTERNS = [
  /Account\./i,
  /Contact\./i,
  /Opportunity\./i,
  /User\./i,
];

export class GenAiPromptTemplateGroundingCheck implements SecurityCheck {
  readonly id = 'genai-prompt-template-grounding';
  readonly name = 'GenAI Prompt Template Grounding & Context';
  readonly category = 'AI & Agents';
  readonly description =
    'Inspects active GenAI Prompt Templates for grounding on System-Mode Flows or without-sharing Apex, and untrusted CRM input interpolation.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let templates: GenAiPromptTemplateRecord[];
    try {
      templates = await ctx.tooling.query<GenAiPromptTemplateRecord>(
        'SELECT Id, DeveloperName, MasterLabel, TemplateType, Description FROM GenAiPromptTemplate',
      );
    } catch (err) {
      if (isMissingObjectError(err)) {
        findings.push({
          id: 'genai-prompt-template-grounding-not-enabled',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'GenAI Prompt Templates are not enabled or configured in this org',
          detail: 'GenAiPromptTemplate object is not available; Prompt Builder / GenAI is not enabled.',
          remediation: 'No action required if Generative AI Prompt Builder is not deployed.',
        });
        return { findings };
      }
      try {
        templates = await ctx.tooling.query<GenAiPromptTemplateRecord>(
          'SELECT Id, DeveloperName, MasterLabel, TemplateType FROM GenAiPromptTemplate',
        );
      } catch (innerErr) {
        findings.push({
          id: 'genai-prompt-template-grounding-inaccessible',
          category: this.category,
          riskLevel: 'INFO',
          inconclusive: true,
          title: 'GenAI Prompt Templates could not be read',
          detail: `Query to GenAiPromptTemplate failed: ${innerErr instanceof Error ? innerErr.message : String(innerErr)}`,
          remediation: 'Ensure the audit user has permission to view GenAI and Prompt Builder configuration.',
        });
        return { findings };
      }
    }

    if (templates.length === 0) {
      findings.push({
        id: 'genai-prompt-template-grounding-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active GenAI Prompt Templates found in the org',
        detail: 'Zero GenAiPromptTemplate records were returned.',
        remediation: 'Review grounding sources whenever new Prompt Templates are created.',
      });
      return { findings };
    }

    // Retrieve active Flows and ApexClasses to correlate grounding sources
    let flows: FlowRecord[] = [];
    try {
      flows = await ctx.tooling.query<FlowRecord>(
        "SELECT Id, DeveloperName, MasterLabel, ProcessType, RunInMode FROM Flow WHERE Status = 'Active'",
      );
    } catch {
      // Degrade gracefully if Flow query fails
    }

    let apexClasses: ApexClassRecord[] = [];
    try {
      apexClasses = await ctx.tooling.query<ApexClassRecord>(
        'SELECT Id, Name, Body FROM ApexClass',
      );
    } catch {
      // Degrade gracefully if ApexClass query fails
    }

    const flowByName = new Map<string, FlowRecord>();
    for (const fl of flows) {
      flowByName.set(fl.DeveloperName.toLowerCase(), fl);
      flowByName.set(fl.MasterLabel.toLowerCase(), fl);
    }

    const apexByName = new Map<string, ApexClassRecord>();
    for (const cls of apexClasses) {
      apexByName.set(cls.Name.toLowerCase(), cls);
    }

    const systemModeFlowTemplates: GenAiPromptTemplateRecord[] = [];
    const withoutSharingApexTemplates: GenAiPromptTemplateRecord[] = [];
    const untrustedInputTemplates: GenAiPromptTemplateRecord[] = [];

    for (const t of templates) {
      const content = `${t.TemplateContent ?? ''} ${t.Description ?? ''} ${t.DeveloperName}`;

      // Check Flow grounding
      for (const [name, fl] of flowByName) {
        if (content.toLowerCase().includes(name)) {
          const runInMode = fl.RunInMode ?? '';
          if (runInMode.toLowerCase().includes('system') || runInMode === 'DefaultMode' || runInMode === '') {
            systemModeFlowTemplates.push(t);
            break;
          }
        }
      }

      // Check Apex grounding
      for (const [name, cls] of apexByName) {
        if (content.toLowerCase().includes(name)) {
          const body = cls.Body ?? '';
          if (/without\s+sharing/i.test(body)) {
            withoutSharingApexTemplates.push(t);
            break;
          }
        }
      }

      // Check untrusted text input interpolation alongside CRM data
      const hasUntrusted = UNTRUSTED_FIELD_PATTERNS.some((p) => p.test(content));
      const hasPrivileged = PRIVILEGED_DATA_PATTERNS.some((p) => p.test(content));
      if (hasUntrusted && hasPrivileged) {
        untrustedInputTemplates.push(t);
      }
    }

    if (systemModeFlowTemplates.length > 0) {
      findings.push({
        id: 'genai-prompt-template-grounding-flow',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${systemModeFlowTemplates.length} Prompt Template(s) grounded on System-Mode Flow`,
        detail:
          'Prompt templates grounded on Flows executing in system context bypass the invoking user\'s record-level sharing, exposing records they cannot view directly.',
        remediation:
          'Set grounding Flows to run in user context ("Run in User Context" or SystemModeWithSharing) to enforce caller record visibility.',
        affectedItems: systemModeFlowTemplates.map((t) => ({
          label: t.MasterLabel || t.DeveloperName,
          url: `${baseUrl}/lightning/setup/PromptTemplate/home`,
          note: 'Template grounded on system-mode Flow',
        })),
      });
    }

    if (withoutSharingApexTemplates.length > 0) {
      findings.push({
        id: 'genai-prompt-template-grounding-apex',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${withoutSharingApexTemplates.length} Prompt Template(s) grounded on Apex running without sharing`,
        detail:
          'Invocable Apex grounding methods declared "without sharing" return unconstrained records, allowing prompt generation to extract CRM records outside the caller\'s access permissions.',
        remediation:
          'Declare grounding Apex classes with "inherited sharing" or "with sharing" to ensure record-level security is enforced during prompt resolution.',
        affectedItems: withoutSharingApexTemplates.map((t) => ({
          label: t.MasterLabel || t.DeveloperName,
          url: `${baseUrl}/lightning/setup/PromptTemplate/home`,
          note: 'Grounding Apex class runs without sharing',
        })),
      });
    }

    if (untrustedInputTemplates.length > 0) {
      findings.push({
        id: 'genai-prompt-template-grounding-untrusted',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${untrustedInputTemplates.length} Prompt Template(s) interpolate untrusted fields with privileged CRM data`,
        detail:
          'Templates interpolating external text fields (e.g. Lead.Description, Case.SuppliedName) alongside sensitive CRM objects allow attackers to inject prompts that extract or manipulate adjacent data.',
        remediation:
          'Separate prompt templates processing untrusted external text from those retrieving privileged internal records, and apply input sanitization guardrails.',
        affectedItems: untrustedInputTemplates.map((t) => ({
          label: t.MasterLabel || t.DeveloperName,
          url: `${baseUrl}/lightning/setup/PromptTemplate/home`,
          note: 'Untrusted input combined with privileged context',
        })),
      });
    }

    if (
      systemModeFlowTemplates.length === 0 &&
      withoutSharingApexTemplates.length === 0 &&
      untrustedInputTemplates.length === 0
    ) {
      findings.push({
        id: 'genai-prompt-template-grounding-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'All evaluated Prompt Templates use safe grounding sources',
        detail: `${templates.length} Prompt Template(s) inspected with no unconstrained system-mode or without-sharing grounding detected.`,
        remediation: 'Continue enforcing user-context execution for all prompt template grounding sources.',
      });
    }

    return { findings };
  }
}
