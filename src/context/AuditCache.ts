// HealthCheckRisk: one row from the Salesforce Health Check API
export interface HealthCheckRisk {
  setting: string;
  riskType: string;
  value: string;
  score: number;
}

// ApexClassBody: the subset of ApexClass fields checks need for scanning
export interface ApexClassBody {
  name: string;
  body: string;
}

// AuditCache is mutable shared state passed through AuditContext.
// Keys are typed — rename any field and every check referencing it gets a compile error.
export interface AuditCache {
  healthCheckRisks?: HealthCheckRisk[];
  apexBodies?: ApexClassBody[];
  namedCredentialEndpoints?: string[];
  remoteSiteUrls?: string[];
  healthCloudInstalled?: boolean;
}
