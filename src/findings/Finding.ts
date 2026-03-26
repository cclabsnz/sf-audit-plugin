import type { RiskLevel } from './RiskLevel.js';

export interface AffectedItem {
  label: string;
  url?: string;
  note?: string;
}

export interface Finding {
  id: string;
  category: string;
  riskLevel: RiskLevel;
  title: string;
  detail: string;
  remediation: string;
  affectedItems?: AffectedItem[];
}
