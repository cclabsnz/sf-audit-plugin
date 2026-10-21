import type { Finding } from './Finding.js';
import type { OrgMetrics } from '@cclabsnz/sf-core';
import type { AttackChain } from '../chains/AttackChain.js';
import type { EvidenceCoverage } from './coverage.js';

export interface AuditResult {
  generatedAt: Date;
  orgId: string;
  orgName: string;
  orgType: string;
  isSandbox: boolean;
  instance: string;
  instanceUrl: string;
  findings: Finding[];
  metrics: OrgMetrics;
  healthScore: number;  // 0–100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  /** What set the grade, e.g. "F: 2 CRITICAL findings (D allows none)". Absent on results stored by older versions. */
  gradeReason?: string;
  attackChains?: AttackChain[];
  /** Findings covered by an approved waiver, also present in `findings` with `waived: true`. */
  waivedFindings?: Finding[];
  /** How much of the audit gathered evidence, and whether that capped the grade. */
  coverage?: EvidenceCoverage & {
    /** True when coverage fell below the bar and the grade was lowered from A to B. */
    gradeCapped: boolean;
  };
}
