import type { AuditContext } from '@cclabsnz/sf-core';
import type { Finding } from '../findings/Finding.js';
import type { AuditCache } from '@cclabsnz/sf-core';
import type { OrgMetrics } from '@cclabsnz/sf-core';

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
