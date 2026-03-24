import type { Finding } from './Finding.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';

export interface AuditResult {
  generatedAt: Date;
  orgId: string;
  orgName: string;
  orgType: string;
  isSandbox: boolean;
  instance: string;
  findings: Finding[];
  metrics: OrgMetrics;
  healthScore: number;  // 0–100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}
