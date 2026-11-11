import type { RiskLevel } from '@cclabsnz/sf-core';
import type { AttackChain } from '../chains/AttackChain.js';
import type { AuditResult } from './AuditResult.js';
import type { Finding } from './Finding.js';

/** How many affected-item labels to keep before falling back to a bare count. */
const SAMPLE_LIMIT = 3;

export interface DigestFinding {
  checkId?: string;
  riskLevel: RiskLevel;
  title: string;
  remediation: string;
  complianceTags?: string[];
  /** Total affected items. Present only when the finding named any. */
  affectedCount?: number;
  /** First few affected labels, for orientation. Never the whole list. */
  affectedSample?: string[];
}

export interface DigestInconclusive {
  checkId?: string;
  title: string;
}

export interface DigestCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  passed: number;
  inconclusive: number;
}

export interface AuditDigest {
  orgId: string;
  orgName: string;
  isSandbox: boolean;
  generatedAt: Date;
  healthScore: number;
  grade: AuditResult['grade'];
  counts: DigestCounts;
  findings: DigestFinding[];
  inconclusive: DigestInconclusive[];
  attackChains: AttackChain[];
}

const isActive = (f: Finding): boolean => f.passed !== true && f.inconclusive !== true;

function toDigestFinding(f: Finding): DigestFinding {
  const out: DigestFinding = {
    checkId: f.checkId,
    riskLevel: f.riskLevel,
    title: f.title,
    remediation: f.remediation,
  };
  if (f.complianceTags !== undefined) out.complianceTags = f.complianceTags;
  if (f.affectedItems !== undefined && f.affectedItems.length > 0) {
    out.affectedCount = f.affectedItems.length;
    out.affectedSample = f.affectedItems.slice(0, SAMPLE_LIMIT).map((i) => i.label);
  }
  return out;
}

function countBy(findings: Finding[]): DigestCounts {
  const counts: DigestCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, passed: 0, inconclusive: 0 };
  for (const f of findings) {
    if (f.passed === true) counts.passed += 1;
    else if (f.inconclusive === true) counts.inconclusive += 1;
    else counts[f.riskLevel.toLowerCase() as Lowercase<RiskLevel>] += 1;
  }
  return counts;
}

/**
 * A token-cheap view of an audit, for callers that reason over the result rather
 * than read it.
 *
 * Passing checks are counted but not listed, `detail` prose is dropped in favour of
 * `remediation`, and affected-item lists — which are unbounded and dominate a large
 * org's report — collapse to a count plus a short sample. Attack chains survive
 * intact: there are few of them and they carry the analysis.
 */
export function buildDigest(result: AuditResult): AuditDigest {
  return {
    orgId: result.orgId,
    orgName: result.orgName,
    isSandbox: result.isSandbox,
    generatedAt: result.generatedAt,
    healthScore: result.healthScore,
    grade: result.grade,
    counts: countBy(result.findings),
    findings: result.findings.filter(isActive).map(toDigestFinding),
    inconclusive: result.findings
      .filter((f) => f.inconclusive === true)
      .map((f) => ({ checkId: f.checkId, title: f.title })),
    attackChains: result.attackChains ?? [],
  };
}
