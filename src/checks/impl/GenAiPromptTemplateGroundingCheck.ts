import type { AuditContext } from '@cclabsnz/sf-core';
import { FlowRepository } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isMissingObjectError } from '../support/missingObject.js';

interface GenAiPromptTemplateRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel: string;
}

interface ApexClassRecord {
  Id: string;
  Name: string;
  Body?: string | null;
}

// A template names its grounding sources explicitly: as a data provider definition
// (flow://Name, apex://Name) or as a merge field ({!$Flow:Name.Prompt}, {!$Apex:Name.Prompt}).
// Matching on those, rather than on a flow or class name appearing anywhere, keeps a template
// that merely mentions a common word from being tied to an unrelated flow.
const FLOW_REF = /(?:flow:\/\/|\$Flow:)([A-Za-z][A-Za-z0-9_]*)/gi;
const APEX_REF = /(?:apex:\/\/|\$Apex:)([A-Za-z][A-Za-z0-9_]*)/gi;

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
        'SELECT Id, DeveloperName, MasterLabel FROM GenAiPromptTemplate',
      );
    } catch (err) {
      if (!isMissingObjectError(err)) throw err;
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

    // The template body, its inputs and its data providers exist only in the Metadata API
    // definition. Without it nothing below can be judged, so the run says so.
    const contentByTemplate = new Map<GenAiPromptTemplateRecord, string>();
    let unread = 0;
    for (const t of templates) {
      let meta: unknown = null;
      if (ctx.metadata) {
        try {
          meta = await ctx.metadata.read('GenAiPromptTemplate', t.DeveloperName);
        } catch {
          meta = null;
        }
      }
      if (meta) contentByTemplate.set(t, stringsIn(meta).join('\n'));
      else unread++;
    }

    const flowRefs = new Map<GenAiPromptTemplateRecord, string[]>();
    const apexRefs = new Map<GenAiPromptTemplateRecord, string[]>();
    for (const [t, content] of contentByTemplate) {
      flowRefs.set(t, refs(content, FLOW_REF));
      apexRefs.set(t, refs(content, APEX_REF));
    }

    // Run mode of each referenced active flow, keyed by API name (lower-cased).
    const flowRunMode = new Map<string, string | null>();
    if ([...flowRefs.values()].some((r) => r.length > 0)) {
      const repo = new FlowRepository(ctx.soql, ctx.tooling);
      const [definitions, active] = await Promise.all([repo.listDefinitions(), repo.listActiveVersions()]);
      const modeByVersion = new Map(active.map((v) => [v.id, v.runInMode]));
      for (const d of definitions) {
        if (d.activeVersionId && modeByVersion.has(d.activeVersionId)) {
          flowRunMode.set(d.apiName.toLowerCase(), modeByVersion.get(d.activeVersionId) ?? null);
        }
      }
    }

    const referencedClasses = [...new Set([...apexRefs.values()].flat())];
    const withoutSharingClasses = new Set<string>();
    if (referencedClasses.length > 0) {
      const names = referencedClasses.map((n) => `'${n}'`).join(', ');
      const classes = await ctx.tooling.query<ApexClassRecord>(
        `SELECT Id, Name, Body FROM ApexClass WHERE Name IN (${names})`,
      );
      for (const cls of classes) {
        if (declaredWithoutSharing(cls.Name, cls.Body ?? '')) withoutSharingClasses.add(cls.Name.toLowerCase());
      }
    }

    const systemModeFlowTemplates: GenAiPromptTemplateRecord[] = [];
    const withoutSharingApexTemplates: GenAiPromptTemplateRecord[] = [];
    const untrustedInputTemplates: GenAiPromptTemplateRecord[] = [];

    for (const [t, content] of contentByTemplate) {
      // Only SystemModeWithoutSharing ignores the running user's record access. DefaultMode and
      // SystemModeWithSharing both still apply sharing.
      if ((flowRefs.get(t) ?? []).some((f) => flowRunMode.get(f) === 'SystemModeWithoutSharing')) {
        systemModeFlowTemplates.push(t);
      }
      if ((apexRefs.get(t) ?? []).some((c) => withoutSharingClasses.has(c))) {
        withoutSharingApexTemplates.push(t);
      }
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

    const anyFinding =
      systemModeFlowTemplates.length > 0 || withoutSharingApexTemplates.length > 0 || untrustedInputTemplates.length > 0;

    if (unread > 0) {
      findings.push({
        id: 'genai-prompt-template-grounding-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: `${unread} of ${templates.length} Prompt Template definition(s) could not be read`,
        detail:
          'A prompt template\'s body, inputs and grounding sources are only in its Metadata API definition. Templates that could not be read were not evaluated for system-mode grounding or untrusted input.',
        remediation: 'Run the audit with a user that can read Prompt Builder metadata (Customize Application or View Setup and Configuration), then re-run.',
      });
    } else if (!anyFinding) {
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

function refs(content: string, pattern: RegExp): string[] {
  return [...new Set([...content.matchAll(pattern)].map((m) => m[1].toLowerCase()))];
}

/** Every string value anywhere in a parsed metadata tree. */
function stringsIn(node: unknown): string[] {
  if (typeof node === 'string') return [node];
  if (Array.isArray(node)) return node.flatMap(stringsIn);
  if (node && typeof node === 'object') return Object.values(node).flatMap(stringsIn);
  return [];
}

/**
 * Whether the declaration of `className` in `body` carries `without sharing`. Literal patterns
 * only, in one linear pass: the name comes from the org, so it never becomes part of a regex.
 */
function declaredWithoutSharing(className: string, body: string): boolean {
  const target = className.toLowerCase();
  const declaration = /\bclass\s+(\w+)/gi;
  for (let m = declaration.exec(body); m !== null; m = declaration.exec(body)) {
    if (m[1].toLowerCase() !== target) continue;
    // The modifiers sit between the previous statement or block boundary and `class`.
    const start = Math.max(body.lastIndexOf(';', m.index), body.lastIndexOf('{', m.index), body.lastIndexOf('}', m.index)) + 1;
    return /\bwithout\s+sharing\b/i.test(body.slice(start, m.index));
  }
  return false;
}

