import { CHECKS } from '../checks/registry.js';
import { domainOf } from '../checks/domains.js';
import { getCheckMeta } from '../findings/CheckMeta.js';
import { getComplianceTags } from '../compliance/resolve.js';
import { buildActionPlan, chainLabels, EFFORT_LABEL, WAVE_LABEL } from './ActionPlan.js';
import type { AuditResult } from '../findings/AuditResult.js';
import type { Finding } from '../findings/Finding.js';

/** How many affected items to show; the report has the rest. */
const SAMPLE = 5;

export interface CheckExplanation {
  id: string;
  name: string;
  description: string;
  domain?: string;
  effort?: string;
  impact?: string;
  complianceTags: string[];
}

export interface FindingExplanation {
  id: string;
  title: string;
  status: 'open' | 'passed' | 'inconclusive' | 'waived' | 'not assessed';
  severity: Finding['riskLevel'];
  detail: string;
  remediation: string;
  affectedCount: number;
  affectedSample: string[];
  /** Chains this finding is a step of, with whether fixing it breaks the chain. */
  chains: Array<{ label: string; title: string; severity: Finding['riskLevel']; breaksChain: boolean }>;
  /** The fix-first action that closes it, if it is open. */
  action?: { rank: number; wave: string; title: string };
}

export interface Explanation {
  check: CheckExplanation;
  finding?: FindingExplanation;
  /** With --file and a check id: that check's findings in the run. */
  findings?: Array<{ id: string; title: string; status: FindingExplanation['status']; severity: Finding['riskLevel'] }>;
}

export const statusOf = (f: Finding): FindingExplanation['status'] =>
  f.waived ? 'waived' : f.notAssessed ? 'not assessed' : f.inconclusive ? 'inconclusive' : f.passed ? 'passed' : 'open';

/** The check a finding id belongs to: the longest check id it starts with. */
export function checkForFindingId(id: string): (typeof CHECKS)[number] | undefined {
  return CHECKS.filter((c) => id === c.id || id.startsWith(`${c.id}-`)).sort((a, b) => b.id.length - a.id.length)[0];
}

export function parseResult(json: string): AuditResult {
  const raw = JSON.parse(json) as { result?: AuditResult } & Partial<AuditResult>;
  const result = (raw.result ?? raw) as AuditResult;
  if (!Array.isArray(result.findings)) throw new Error('not a full audit result');
  return result;
}

/** Why an explanation could not be built; the command turns it into a CLI error with this advice. */
export class ExplainError extends Error {
  constructor(message: string, readonly suggestion: string) {
    super(message);
  }
}

/**
 * Explain a check id, or a finding id from a run. With a run and the check's own id, list that
 * check's findings in the run. Throws ExplainError for an unknown id or a finding not in the run.
 */
export function explain(id: string, result?: AuditResult): Explanation {
  // A finding id does not always start with its check's id (apex-no-sharing-declaration is
  // apex-sharing's), so a run's own checkId wins; the prefix is the fallback without one.
  const inRun = result?.findings.find((f) => f.id === id);
  const check =
    CHECKS.find((c) => c.id === (inRun?.checkId ?? id)) ?? checkForFindingId(id);
  if (!check) {
    throw new ExplainError(
      `No check or finding id matches '${id}'.`,
      result ? "Run 'sf audit list' for check ids." : "Run 'sf audit list' for check ids, or pass the run's report with --file to explain a finding.",
    );
  }
  const meta = getCheckMeta(check.id);
  const out: Explanation = {
    check: {
      id: check.id,
      name: check.name,
      description: check.description,
      domain: domainOf(check.id),
      effort: meta ? EFFORT_LABEL[meta.effort] : undefined,
      impact: meta?.impact,
      complianceTags: getComplianceTags(check.id),
    },
  };
  if (!result) return out;
  if (inRun) {
    out.finding = explainFinding(inRun, result);
  } else if (id === check.id) {
    out.findings = result.findings
      .filter((f) => f.checkId === check.id)
      .map((f) => ({ id: f.id, title: f.title, status: statusOf(f), severity: f.riskLevel }));
  } else {
    throw new ExplainError(`Finding '${id}' is not in this run.`, `Explain ${check.id} with the same file to list that check's findings.`);
  }
  return out;
}

function explainFinding(f: Finding, result: AuditResult): FindingExplanation {
  const chains = result.attackChains ?? [];
  const labels = chainLabels(chains);
  const plan = buildActionPlan(result.findings, chains);
  const rank = plan.findIndex((a) => a.fixes.some((x) => x.id === f.id && x.checkId === f.checkId));
  const items = f.affectedItems ?? [];
  const out: FindingExplanation = {
    id: f.id,
    title: f.title,
    status: statusOf(f),
    severity: f.riskLevel,
    detail: f.detail,
    remediation: f.remediation,
    affectedCount: items.length,
    affectedSample: items.slice(0, SAMPLE).map((i) => i.label),
    chains: chains.flatMap((c, i) => {
      const step = c.steps.find((s) => s.findingId === f.id);
      return step ? [{ label: labels[i], title: c.title, severity: c.severity, breaksChain: step.breaksChain === true }] : [];
    }),
  };
  if (rank >= 0) out.action = { rank: rank + 1, wave: WAVE_LABEL[plan[rank].wave], title: plan[rank].title };
  return out;
}
