import type { RiskLevel } from '@cclabsnz/sf-core';
import type { Finding } from '../findings/Finding.js';
import type { AttackChain } from '../chains/AttackChain.js';
import { getCheckMeta, type CheckMeta } from '../findings/CheckMeta.js';

type Effort = CheckMeta['effort'];

/** One thing to do, with everything it fixes. The executive report's plan is a list of these. */
export interface PlannedAction {
  /** What to do, as an instruction. */
  title: string;
  /** The specifics, when the instruction names them after a colon ("Close X: A, B and C"). */
  detail?: string;
  /** Why it matters, in one sentence. */
  why: string;
  /** The open findings this action closes. */
  fixes: Finding[];
  /** Indexes into the chains passed in, of the named chains this action breaks: it closes every finding of their break point. */
  breaks: number[];
  /**
   * Named chains whose break point this action works on but cannot finish, because part of the break
   * point is waived or already passed: fixing the open part leaves the chain standing.
   */
  weakens: number[];
  /** Indexes of chains its findings take part in without being the break point. */
  inChains: number[];
  severity: RiskLevel;
  effort: Effort;
  /** 1 = start this week, 2 = this month, 3 = this quarter. */
  wave: 1 | 2 | 3;
  /** Relative weight of the exposure it removes; used to rank and to place it on the matrix. */
  risk: number;
}

const RANK: Record<RiskLevel, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const WEIGHT: Record<RiskLevel, number> = { CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0 };
const EFFORT_RANK: Record<Effort, number> = { quick: 0, moderate: 1, project: 2 };

const isOpen = (f: Finding): boolean => !f.passed && !f.inconclusive && !f.notAssessed && !f.waived;
const worst = (levels: RiskLevel[]): RiskLevel => levels.reduce((a, b) => (RANK[b] < RANK[a] ? b : a), 'INFO' as RiskLevel);
const effortOf = (f: Finding): Effort => (f.checkId && getCheckMeta(f.checkId)?.effort) || 'moderate';

/** The first sentence of a remediation, which the checks write as an instruction. Abbreviations do not end it. */
function firstSentence(text: string): string {
  const m = /^(.+?(?<!\b(?:e\.g|i\.e|etc|vs))[.!?])(\s+(?=[A-Z"(])|$)/s.exec(text.trim());
  return (m ? m[1] : text.trim()).replace(/\s+/g, ' ');
}

/** "Do X: the specifics" splits into a short instruction and its specifics. */
function splitInstruction(text: string): { title: string; detail?: string } {
  const i = text.indexOf(': ');
  // A navigation path ("Setup → X: do Y") or a URL before the colon is not an instruction to lead with.
  if (i < 12 || i > 90 || /→|:\/\//.test(text.slice(0, i))) return { title: text };
  const detail = text.slice(i + 2).trim();
  return { title: text.slice(0, i).trim(), detail: detail.charAt(0).toUpperCase() + detail.slice(1) };
}

/**
 * Turn findings and attack chains into a ranked plan. Each named chain's break point becomes one
 * action (chains sharing a break point share the action); every other open CRITICAL or HIGH finding
 * becomes an action per check. MEDIUM and LOW fixes stay in the roadmap.
 *
 * Wave 1 is anything that breaks a CRITICAL chain or closes a CRITICAL finding; otherwise weeks of
 * work is wave 3 and the rest wave 2. Within a wave, the most risk removed comes first.
 */
export function buildActionPlan(findings: Finding[], chains: AttackChain[]): PlannedAction[] {
  const open = findings.filter(isOpen);
  const openById = new Map<string, Finding>();
  for (const f of open) if (!openById.has(f.id)) openById.set(f.id, f);

  const chainsOf = new Map<string, number[]>();
  chains.forEach((c, i) => {
    for (const s of c.steps) chainsOf.set(s.findingId, [...new Set([...(chainsOf.get(s.findingId) ?? []), i])]);
  });

  const actions: PlannedAction[] = [];
  const byBreakPoint = new Map<string, PlannedAction>();
  chains.forEach((c, i) => {
    if (!c.abuseCase) return;
    const breakIds = [...new Set(c.steps.filter((s) => s.breaksChain).map((s) => s.findingId))];
    const fixes = breakIds.map((id) => openById.get(id)).filter((f): f is Finding => !!f);
    if (fixes.length === 0) return;
    // The chain breaks only when every break-point finding is fixed; a waived or passed one stays.
    const complete = fixes.length === breakIds.length;
    const existing = byBreakPoint.get(c.abuseCase.breakPoint);
    if (existing) {
      (complete ? existing.breaks : existing.weakens).push(i);
      for (const f of fixes) if (!existing.fixes.includes(f)) existing.fixes.push(f);
      return;
    }
    const action: PlannedAction = {
      ...splitInstruction(c.abuseCase.breakPoint),
      why: `Stops ${c.abuseCase.actor} who wants to ${c.abuseCase.goal}.`,
      fixes, breaks: complete ? [i] : [], weakens: complete ? [] : [i], inChains: [], severity: 'INFO', effort: 'quick', wave: 2, risk: 0,
    };
    byBreakPoint.set(c.abuseCase.breakPoint, action);
    actions.push(action);
  });

  const covered = new Set(actions.flatMap((a) => a.fixes));
  const byCheck = new Map<string, Finding[]>();
  for (const f of open) {
    if (covered.has(f) || (f.riskLevel !== 'CRITICAL' && f.riskLevel !== 'HIGH')) continue;
    const key = f.checkId ?? f.id;
    byCheck.set(key, [...(byCheck.get(key) ?? []), f]);
  }
  for (const fixes of byCheck.values()) {
    fixes.sort((a, b) => RANK[a.riskLevel] - RANK[b.riskLevel]);
    const lead = fixes[0];
    actions.push({
      ...splitInstruction(firstSentence(lead.remediation)),
      why: (lead.checkId && getCheckMeta(lead.checkId)?.impact) || lead.title,
      fixes, breaks: [], weakens: [], inChains: [], severity: 'INFO', effort: 'quick', wave: 2, risk: 0,
    });
  }

  for (const a of actions) {
    a.title = a.title.replace(/\.$/, '');
    a.why = a.why.charAt(0).toUpperCase() + a.why.slice(1);
    const broken = a.breaks.map((i) => chains[i]);
    a.inChains = [...new Set(a.fixes.flatMap((f) => chainsOf.get(f.id) ?? []))]
      .filter((i) => !a.breaks.includes(i) && !a.weakens.includes(i)).sort((x, y) => x - y);
    a.severity = worst([...a.fixes.map((f) => f.riskLevel), ...[...a.breaks, ...a.weakens].map((i) => chains[i].severity)]);
    a.effort = a.fixes.map(effortOf).reduce((x, y) => (EFFORT_RANK[y] > EFFORT_RANK[x] ? y : x), 'quick' as Effort);
    // A broken chain counts double: it removes a whole path, not one weakness.
    a.risk = a.fixes.reduce((n, f) => n + WEIGHT[f.riskLevel], 0) + broken.reduce((n, c) => n + 2 * WEIGHT[c.severity], 0);
    a.wave = a.severity === 'CRITICAL' ? 1 : a.effort === 'project' ? 3 : 2;
  }

  return actions.sort((a, b) => a.wave - b.wave || b.risk - a.risk || a.title.localeCompare(b.title));
}

/** How long an action takes, in the words both reports print. */
/** Chain labels as the executive report prints them: C1… for named chains, P1… for potential ones. */
export function chainLabels(chains: AttackChain[]): string[] {
  let c = 0, p = 0;
  return chains.map((ch) => (ch.abuseCase ? `C${++c}` : `P${++p}`));
}

export const EFFORT_LABEL = { quick: 'Under a day', moderate: 'Days', project: 'Weeks' } as const;
/** When to start each wave. */
export const WAVE_LABEL = { 1: 'Start now', 2: 'Next 30 days', 3: 'This quarter' } as const;
/** Why an action sits in its wave. */
export const WAVE_WHY = {
  1: 'breaks a critical chain or closes a critical finding, whatever the effort',
  2: 'high severity, days of work or less',
  3: 'high severity, weeks of work',
} as const;

const NUMBER_WORDS = ['No', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine', 'Ten'];
const countWord = (n: number): string => NUMBER_WORDS[n] ?? String(n);
const actionsWord = (n: number): string => `${countWord(n)} action${n === 1 ? '' : 's'}`;
const verb = (n: number, one: string, many: string): string => (n === 1 ? one : many);

/**
 * The plan's conclusion in one sentence: the executive summary's headline and the technical report's
 * "fix first" title, so both reports state the same answer.
 */
export function planHeadline(plan: PlannedAction[], chains: AttackChain[], openHigh: number): string {
  // Every critical chain, potential ones too: a path is only "closed" when an action breaks it.
  const allCrit = chains.map((c, i) => ({ c, i })).filter((x) => x.c.severity === 'CRITICAL');
  const wave1 = plan.filter((a) => a.wave === 1);
  const brokenByWave1 = new Set(wave1.flatMap((a) => a.breaks));
  const allCritBroken = allCrit.length > 0 && allCrit.every((x) => brokenByWave1.has(x.i));
  const rest = plan.length - wave1.length;
  const restText = rest ? `; ${rest} more action${verb(rest, ' completes', 's complete')} the plan` : '';
  const n1 = wave1.length;
  if (plan.length === 0) return 'No critical or high-severity issues are open; the remaining fixes are routine hardening';
  if (allCritBroken) return `${actionsWord(n1)} to start now ${verb(n1, 'closes', 'close')} every critical attack path${restText}`;
  if (n1) return `${actionsWord(n1)} to start now ${verb(n1, 'addresses', 'address')} the critical exposure${restText}`;
  if (openHigh) return `${actionsWord(plan.length)} ${verb(plan.length, 'addresses', 'address')} every open high-severity issue; none is critical`;
  return `${actionsWord(plan.length)} ${verb(plan.length, 'addresses', 'address')} the remaining exposure; none is critical or high`;
}
