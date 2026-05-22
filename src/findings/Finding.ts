import type { RiskLevel } from './RiskLevel.js';

export interface AffectedItem {
  label: string;
  url?: string;
  note?: string;
}

export interface Finding {
  id: string;
  /**
   * The ID of the check that produced this finding.
   *
   * This field is optional on the interface so that the 22+ individual check implementations
   * can construct `Finding` objects without declaring it — doing so would otherwise cause
   * TypeScript compile errors throughout the codebase. The `CheckEngine` is the single place
   * that sets this value after each check runs. Consumers of `AuditResult.findings` can
   * therefore rely on `checkId` being present on every finding in a completed audit result.
   */
  checkId?: string;
  category: string;
  riskLevel: RiskLevel;
  title: string;
  detail: string;
  remediation: string;
  affectedItems?: AffectedItem[];
  /** True when the finding represents a passing check (everything is correctly configured). */
  passed?: boolean;
  /**
   * Compliance framework tags, e.g. ['OWASP-A01', 'SOC2-CC6.1'].
   * Populated by CheckEngine from ComplianceMapping after each check runs.
   */
  complianceTags?: string[];
  /**
   * True when the check could not gather evidence due to insufficient permissions.
   * Scored as INFO (no impact on health score) but displayed distinctly.
   */
  inconclusive?: boolean;
}
