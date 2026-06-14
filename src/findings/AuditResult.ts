import type { Finding } from './Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';
import type { AttackChain } from '../chains/AttackChain.js';

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
  attackChains?: AttackChain[];
}
