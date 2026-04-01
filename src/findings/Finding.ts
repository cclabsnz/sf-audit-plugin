import type { RiskLevel } from './RiskLevel.js';

export interface AffectedItem {
  label: string;
  url?: string;
  note?: string;
}

export interface Finding {
  id: string;
  /** The ID of the check that produced this finding. Set by CheckEngine; not required of individual check implementations. */
  checkId?: string;
  category: string;
  riskLevel: RiskLevel;
  title: string;
  detail: string;
  remediation: string;
  affectedItems?: AffectedItem[];
}
