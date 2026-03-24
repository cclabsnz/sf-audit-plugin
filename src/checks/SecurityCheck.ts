import type { AuditContext } from '../context/AuditContext.js';
import type { Finding } from '../findings/Finding.js';
import type { AuditCache } from '../context/AuditCache.js';
import type { OrgMetrics } from '../context/OrgMetrics.js';

export interface CheckResult {
  findings: Finding[];
  metrics?: Partial<OrgMetrics>;
}

export interface SecurityCheck {
  readonly id: string;
  readonly name: string;
  readonly category: string;
  readonly description: string;

  readonly dependsOnCache?: ReadonlyArray<keyof AuditCache>;
  readonly populatesCache?: ReadonlyArray<keyof AuditCache>;

  run(ctx: AuditContext): Promise<CheckResult>;
}
