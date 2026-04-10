import type { OrgMetrics } from '../context/OrgMetrics.js';

export interface MetricMeta {
  label: string;
  /** Which direction means "getting better"? */
  improvedWhen: 'higher' | 'lower' | 'neutral';
}

// Every key of OrgMetrics must have an entry here.
export const METRIC_META: Record<keyof OrgMetrics, MetricMeta> = {
  totalActiveUsers:           { label: 'Total Active Users',             improvedWhen: 'neutral' },
  modifyAllDataUsersCount:    { label: 'Modify All Data Users',          improvedWhen: 'lower'   },
  viewAllDataUsersCount:      { label: 'View All Data Users',            improvedWhen: 'lower'   },
  permissionSetCount:         { label: 'Permission Sets',                improvedWhen: 'neutral' },
  profileCount:               { label: 'Profiles',                       improvedWhen: 'neutral' },
  apexClassCount:             { label: 'Apex Classes',                   improvedWhen: 'neutral' },
  apexTriggerCount:           { label: 'Apex Triggers',                  improvedWhen: 'neutral' },
  codeCoveragePercent:        { label: 'Code Coverage %',                improvedWhen: 'higher'  },
  failedLogins30d:            { label: 'Failed Logins (30d)',            improvedWhen: 'lower'   },
  inactiveUsers90d:           { label: 'Inactive Users (90d)',           improvedWhen: 'lower'   },
  connectedAppsCount:         { label: 'Connected Apps',                 improvedWhen: 'neutral' },
  remoteSitesCount:           { label: 'Remote Site Settings',           improvedWhen: 'neutral' },
  insecureRemoteSitesCount:   { label: 'Insecure Remote Sites',          improvedWhen: 'lower'   },
  namedCredentialsCount:      { label: 'Named Credentials',              improvedWhen: 'neutral' },
  unusedNamedCredentialsCount:{ label: 'Unused Named Credentials',       improvedWhen: 'lower'   },
  healthCheckScore:           { label: 'Health Check Score',             improvedWhen: 'higher'  },
};

export function metricDirection(
  key: keyof OrgMetrics,
  before: number,
  after: number,
): 'improved' | 'degraded' | 'neutral' {
  const meta = METRIC_META[key];
  if (meta.improvedWhen === 'neutral' || before === after) return 'neutral';
  if (meta.improvedWhen === 'higher') return after > before ? 'improved' : 'degraded';
  return after < before ? 'improved' : 'degraded';
}
