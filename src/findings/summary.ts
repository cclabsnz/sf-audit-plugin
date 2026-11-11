import type { AuditResult } from './AuditResult.js';
import type { Finding } from './Finding.js';
import { findingStatus, openCounts } from './status.js';
import { buildActionPlan, chainLabels, planHeadline, EFFORT_LABEL, WAVE_LABEL } from '../report/ActionPlan.js';

export interface SummaryAction {
  rank: number;
  wave: (typeof WAVE_LABEL)[keyof typeof WAVE_LABEL];
  title: string;
  severity: Finding['riskLevel'];
  effort: (typeof EFFORT_LABEL)[keyof typeof EFFORT_LABEL];
  /** Ids of the open findings it closes. */
  closes: string[];
  /** Labels (C1, P1…) of the chains it breaks. */
  breaks: string[];
  /** Labels of chains its findings take part in without breaking them. */
  partOf: string[];
}

export interface SummaryChain {
  label: string;
  id: string;
  title: string;
  severity: Finding['riskLevel'];
  /** The fix that stops the chain; named chains only. */
  breakPoint?: string;
  steps: number;
}

export interface AuditSummary {
  orgId: string;
  orgName: string;
  isSandbox: boolean;
  generatedAt: Date;
  grade: AuditResult['grade'];
  healthScore: number;
  gradeReason?: string;
  coverage?: { percent: number; checksAssessed: number; checksRun: number; notAssessed: string[] };
  /** Open findings by severity, as page one counts them, plus the other statuses. */
  counts: { open: Record<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW', number>; info: number; waived: number; inconclusive: number; passed: number };
  /** The plan's conclusion in one sentence, as both reports state it. */
  headline: string;
  actions: SummaryAction[];
  attackChains: SummaryChain[];
}


/**
 * Page one of the report as data: grade and why, coverage, the fix-first plan and the attack paths.
 * Smaller than the digest because it lists actions, not findings: each action names the finding ids it
 * closes, and `sf audit explain <id>` gives the rest. Built for agents that triage before they read.
 */
export function buildSummary(result: AuditResult): AuditSummary {
  const chains = result.attackChains ?? [];
  const labels = chainLabels(chains);
  const plan = buildActionPlan(result.findings, chains);
  const open = openCounts(result);
  const tally = (s: string) => result.findings.filter((f) => findingStatus(f) === s).length;
  const out: AuditSummary = {
    orgId: result.orgId,
    orgName: result.orgName,
    isSandbox: result.isSandbox,
    generatedAt: result.generatedAt,
    grade: result.grade,
    healthScore: result.healthScore,
    counts: { open, info: tally('info'), waived: tally('waived'), inconclusive: tally('inconclusive'), passed: tally('passed') },
    headline: planHeadline(plan, chains, open.HIGH),
    actions: plan.map((a, i) => ({
      rank: i + 1,
      wave: WAVE_LABEL[a.wave],
      title: a.title,
      severity: a.severity,
      effort: EFFORT_LABEL[a.effort],
      closes: a.fixes.map((f) => f.id),
      breaks: a.breaks.map((n) => labels[n]),
      partOf: a.inChains.map((n) => labels[n]),
    })),
    attackChains: chains.map((c, i) => {
      const chain: SummaryChain = { label: labels[i], id: c.id, title: c.title, severity: c.severity, steps: c.steps.length };
      if (c.abuseCase) chain.breakPoint = c.abuseCase.breakPoint;
      return chain;
    }),
  };
  if (result.gradeReason !== undefined) out.gradeReason = result.gradeReason;
  if (result.coverage) {
    const { percent, checksAssessed, checksRun, notAssessed } = result.coverage;
    out.coverage = { percent, checksAssessed, checksRun, notAssessed };
  }
  return out;
}
