import type { RiskLevel } from './RiskLevel.js';

export interface Finding {
  id: string;
  category: string;
  riskLevel: RiskLevel;
  title: string;
  detail: string;
  remediation: string;
  affectedItems?: string[];
}
