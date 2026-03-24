export interface OrgMetrics {
  totalActiveUsers: number;
  modifyAllDataUsersCount: number;
  viewAllDataUsersCount: number;
  permissionSetCount: number;
  profileCount: number;
  apexClassCount: number;
  apexTriggerCount: number;
  codeCoveragePercent: number;
  failedLogins30d: number;
  inactiveUsers90d: number;
  connectedAppsCount: number;
  remoteSitesCount: number;
  namedCredentialsCount: number;
  healthCheckScore: number;
}

// Used by scoring.ts to fill any metrics not populated by checks
export const EMPTY_METRICS: OrgMetrics = {
  totalActiveUsers: 0,
  modifyAllDataUsersCount: 0,
  viewAllDataUsersCount: 0,
  permissionSetCount: 0,
  profileCount: 0,
  apexClassCount: 0,
  apexTriggerCount: 0,
  codeCoveragePercent: 0,
  failedLogins30d: 0,
  inactiveUsers90d: 0,
  connectedAppsCount: 0,
  remoteSitesCount: 0,
  namedCredentialsCount: 0,
  healthCheckScore: 0,
};
