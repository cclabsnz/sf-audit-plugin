import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ApexClassVersionRecord {
  Id: string;
  Name: string;
  ApiVersion: number;
}

interface SoapRemoteProxyRecord {
  Id: string;
  SiteName: string;
  EndpointUrl: string;
}

// API v50 = Winter '21. Classes below this miss 4+ years of platform security improvements.
// API v30 = Spring '14. Classes at or below this may rely on behaviors Salesforce has since deprecated.
const OLD_API_THRESHOLD = 50;
const CRITICAL_API_THRESHOLD = 30;

export class LegacyApiVersionCheck implements SecurityCheck {
  readonly id = 'legacy-api-version';
  readonly name = 'Legacy API Versions';
  readonly category = 'Platform Hygiene';
  readonly description = 'Flags Apex classes compiled on old API versions and detects SOAP-based remote site integrations';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const apexClassesUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ApexClasses/home`;

    // Q1: Fetch Apex classes compiled below the threshold.
    // ORDER BY ApiVersion ASC means index 0 = oldest (minimum), used for risk determination.
    const oldClasses = await ctx.tooling.query<ApexClassVersionRecord>(
      `SELECT Id, Name, ApiVersion FROM ApexClass WHERE NamespacePrefix = null AND ApiVersion < ${OLD_API_THRESHOLD} ORDER BY ApiVersion ASC LIMIT 50`
    );

    if (oldClasses.length === 0) {
      findings.push({
        id: 'legacy-api-version-apex-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `All custom Apex classes are compiled on API v${OLD_API_THRESHOLD}+ (Winter '21 or later)`,
        detail: 'No custom Apex classes with API versions older than the baseline threshold were found. Modern API versions ensure classes benefit from current platform security behaviors and FLS enforcement.',
        remediation: 'When developing new Apex classes, target the current API version. Periodically update old classes and regression-test to stay current.',
      });
    } else {
      const minVer = oldClasses[0].ApiVersion;
      const count = oldClasses.length;
      const hitLimit = count === 50;

      let riskLevel: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
      if (minVer <= CRITICAL_API_THRESHOLD) {
        riskLevel = 'HIGH';
      } else if (minVer < 40 || count > 10) {
        riskLevel = 'MEDIUM';
      }

      findings.push({
        id: 'legacy-api-version-apex',
        category: this.category,
        riskLevel,
        title: `${hitLimit ? '50+' : count} custom Apex class(es) compiled on API v${OLD_API_THRESHOLD - 1} or older (oldest: v${minVer})`,
        detail:
          `Apex classes compiled on old API versions run against older Salesforce platform behaviors that predate security improvements introduced in later releases. API v${CRITICAL_API_THRESHOLD} (Spring '14) and below may rely on deprecated FLS and sharing model defaults that newer versions enforce more strictly. Updating the API version causes the class to compile against the current platform contract but may surface new runtime behaviors that require testing.`,
        remediation:
          `Open each affected class in Developer Console or VS Code, increment the API version to the current release, then run all related tests. Classes using old DML/SOQL patterns may need refactoring to pass FLS checks enforced in newer API versions. Prioritize classes that perform DML or handle sensitive data.`,
        affectedItems: oldClasses.map((c) => ({
          label: c.Name,
          url: apexClassesUrl,
          note: `API v${c.ApiVersion}`,
        })),
      });
    }

    // Q2: Detect active remote sites configured for SOAP-based endpoints.
    // /services/Soap/ in the URL indicates a WSDL/SOAP integration (Salesforce or third-party).
    try {
      const soapRemoteSites = await ctx.tooling.query<SoapRemoteProxyRecord>(
        "SELECT Id, SiteName, EndpointUrl FROM RemoteProxy WHERE IsActive = true AND EndpointUrl LIKE '%/services/Soap/%'"
      );

      if (soapRemoteSites.length > 0) {
        findings.push({
          id: 'legacy-api-soap-remote-sites',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `${soapRemoteSites.length} active remote site setting(s) point to SOAP API endpoints (outbound callouts)`,
          detail:
            'Remote site settings with /services/Soap/ endpoints indicate Apex code making outbound WSDL-based SOAP callouts rather than REST. These integrations are harder to maintain, often pin outdated API versions, and typically require broader API Enabled permissions.',
          remediation:
            'Review each SOAP remote site and evaluate whether a REST equivalent exists. For Salesforce-to-Salesforce integrations, migrate to REST API or Salesforce Connect. For third-party SOAP services, check for a REST endpoint. If SOAP is necessary, document the justification and confirm the pinned API version is current.',
          affectedItems: soapRemoteSites.map((r) => ({
            label: r.SiteName,
            url: `${ctx.orgInfo.instanceUrl}/lightning/setup/SecurityRemoteProxy/home`,
            note: r.EndpointUrl,
          })),
        });
      }
    } catch {
      // RemoteProxy LIKE query may not be supported in all org editions — skip silently.
      // RemoteSitesCheck covers general remote site access concerns.
    }

    // Advisory: inbound SOAP API detection requires EventLogFile CSV analysis.
    // Salesforce stores API_TYPE per-call in EventLogFile (EventType = 'API'):
    //   'E' = Enterprise WSDL (SOAP), 'P' = Partner WSDL (SOAP), 'R' = REST, 'T' = Tooling
    // LoginHistory.LoginType cannot distinguish SOAP logins from UI logins — both show 'Application'.
    findings.push({
      id: 'legacy-api-soap-inbound-advisory',
      category: this.category,
      riskLevel: 'INFO',
      title: 'Inbound SOAP API usage: manual review required via Event Monitoring',
      detail:
        'Salesforce does not expose inbound SOAP API call details in SOQL-queryable objects — they are captured only in EventLogFile with EventType = "API". The API_TYPE column in those log files distinguishes SOAP callers: "E" = Enterprise WSDL, "P" = Partner WSDL. LoginHistory cannot make this distinction; SOAP login() calls and UI logins both appear as LoginType = "Application". If external systems are calling this org via the Enterprise or Partner WSDL, those callers should be migrated to REST API or connected-app-governed OAuth flows.',
      remediation:
        'In Setup → Event Monitoring, download an API event log and filter on API_TYPE = "E" or "P" to identify active SOAP callers. For each SOAP caller, work with the integration owner to migrate to REST API using a connected app with appropriate OAuth scopes and IP restrictions.',
    });

    return { findings };
  }
}
