import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface AuditTrailRecord {
  CreatedDate: string;
  CreatedBy: { Id: string; Username: string; Profile?: { Name: string } };
  Section: string;
  Action: string;
  Display: string;
}

// CI/CD and deployment tooling name patterns — presence in Connected App names signals
// a pipeline-based workflow exists (SBS-DEP-001 positive indicator)
const CI_CD_APP_PATTERNS = [
  /jenkins/i, /github/i, /gitlab/i, /azure[\s-]*devops/i, /bitbucket/i,
  /circleci/i, /travis/i, /copado/i, /gearset/i, /autorabit/i,
  /flosum/i, /ownbackup/i, /metazoa/i, /pipeline/i, /deploy/i,
];

const ADMIN_PROFILE_RE = /admin|system administrator/i;

export class DeploymentIdentityCheck implements SecurityCheck {
  readonly id = 'deployment-identity';
  readonly name = 'Deployment Identity';
  readonly category = 'Deployments';
  readonly description = 'SBS-DEP-001/003: checks for a designated deployment identity and monitors for uncontrolled deployment activity';

  // connectedAppNames is written by ConnectedAppsCheck at zero extra cost
  readonly dependsOnCache = ['connectedAppNames'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const auditUrl = `${baseUrl}/lightning/setup/AuditTrail/home`;
    const connectedAppsUrl = `${baseUrl}/lightning/setup/ConnectedApplication/home`;

    // Signal 1 (cache, zero cost): CI/CD-named Connected Apps indicate a pipeline exists.
    const connectedAppNames = ctx.cache.connectedAppNames ?? [];
    const ciCdApps = connectedAppNames.filter((name) =>
      CI_CD_APP_PATTERNS.some((p) => p.test(name))
    );

    if (ciCdApps.length > 0) {
      findings.push({
        id: 'deployment-cicd-apps-found',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${ciCdApps.length} CI/CD-related Connected App(s) detected — pipeline deployment likely in use`,
        detail:
          'SBS-DEP-001 requires all deployments to be performed by a designated deployment identity, not individual admin accounts. Connected Apps with CI/CD tool names indicate pipeline-based deployments are in use, which is consistent with a controlled deployment process.',
        remediation:
          'Confirm each CI/CD app authenticates as a dedicated deployment service account (not a shared admin user). Document the deployment identity and its owner in the system of record.',
        affectedItems: ciCdApps.map((name) => ({
          label: name,
          url: connectedAppsUrl,
          note: 'CI/CD Connected App — verify it uses a named, dedicated deployment user',
        })),
      });
    }

    // Signal 2 (1 query): SetupAuditTrail entries in deploy-related sections over 90 days.
    // This reveals how many distinct users are performing deployment operations and whether
    // those users are individual admins rather than a designated deployment identity.
    let deployRecords: AuditTrailRecord[];
    try {
      deployRecords = await ctx.soql.queryAll<AuditTrailRecord>(
        `SELECT CreatedDate, CreatedBy.Id, CreatedBy.Username, CreatedBy.Profile.Name,
                Section, Action, Display
         FROM SetupAuditTrail
         WHERE CreatedDate > LAST_N_DAYS:90
           AND Section IN ('Change Sets', 'Developer Tools', 'Packages', 'Metadata')
         ORDER BY CreatedDate DESC
         LIMIT 300`
      );
    } catch {
      findings.push({
        id: 'deployment-audit-trail-inaccessible',
        category: this.category,
        riskLevel: 'MEDIUM',
        inconclusive: true,
        title: 'Deployment audit trail could not be read — SBS-DEP-003 unverified',
        detail:
          'SetupAuditTrail was not accessible. Deployment activity from the past 90 days cannot be analyzed for unauthorized modifications. Without this data it is impossible to determine whether deployments are performed by a single designated identity.',
        remediation:
          'Grant "View Setup and Configuration" permission to the audit user to enable audit trail analysis.',
      });
      return { findings };
    }

    if (deployRecords.length === 0 && ciCdApps.length === 0) {
      findings.push({
        id: 'deployment-no-activity',
        category: this.category,
        riskLevel: 'INFO',
        title: 'No deployment activity detected in the last 90 days — SBS-DEP-001/003',
        detail:
          'SBS-DEP-001 requires a designated deployment identity. No deployment-related SetupAuditTrail entries (Change Sets, Developer Tools, Packages, Metadata sections) and no CI/CD-named Connected Apps were found. Deployments via SF CLI JWT flow or Metadata API may not appear in the audit trail.',
        remediation:
          'Verify deployment processes are documented with a designated identity. If using SF CLI with JWT, confirm the authenticating user is a dedicated service account, not an individual admin.',
      });
      return { findings };
    }

    if (deployRecords.length > 0) {
      // Group by user to find unique deployers
      const byUser = new Map<string, { username: string; profile: string; count: number; latest: string }>();
      for (const r of deployRecords) {
        const uid = r.CreatedBy.Id;
        const existing = byUser.get(uid);
        if (existing) {
          existing.count++;
        } else {
          byUser.set(uid, {
            username: r.CreatedBy.Username,
            profile: r.CreatedBy.Profile?.Name ?? 'Unknown',
            count: 1,
            latest: r.CreatedDate,
          });
        }
      }

      const uniqueDeployers = [...byUser.values()];
      const adminDeployers = uniqueDeployers.filter((u) => ADMIN_PROFILE_RE.test(u.profile));

      // SBS-DEP-001: all deployments should come from a single designated identity
      if (uniqueDeployers.length > 1) {
        findings.push({
          id: 'deployment-multiple-identities',
          category: this.category,
          riskLevel: uniqueDeployers.length > 3 ? 'HIGH' : 'MEDIUM',
          title: `${uniqueDeployers.length} distinct user(s) performed deployment actions in the last 90 days — SBS-DEP-001`,
          detail:
            `SBS-DEP-001 requires all deployments to be performed by a single designated deployment identity, not individual user accounts. ${uniqueDeployers.length} distinct users were found in deployment-related audit trail entries (Change Sets, Developer Tools, Packages, Metadata) over the past 90 days. Multiple deployers make it harder to audit changes and bypass change-management controls.`,
          remediation:
            'Centralise deployments through a CI/CD pipeline that authenticates as a single named service account. Revoke direct deployment access from individual admin users.',
          affectedItems: uniqueDeployers.map(({ username, profile, count, latest }) => ({
            label: username,
            url: auditUrl,
            note: `${count} deployment action(s) | last: ${new Date(latest).toISOString().split('T')[0]} | profile: ${profile}`,
          })),
        });
      } else if (uniqueDeployers.length === 1) {
        const d = uniqueDeployers[0];
        findings.push({
          id: 'deployment-single-identity',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'All deployment activity in the last 90 days came from a single identity — SBS-DEP-001',
          detail:
            `SBS-DEP-001 requires a designated deployment identity. All ${deployRecords.length} deployment-related audit trail entries over 90 days originate from the same user: ${d.username} (${d.profile}).`,
          remediation: 'Document this identity as the designated deployment user in your system of record. Verify it is a service account and not a personal admin account.',
        });
      }

      // SBS-DEP-003: admin-profile deployers are a monitoring risk (human, not CI accounts)
      if (adminDeployers.length > 0) {
        findings.push({
          id: 'deployment-admin-accounts',
          category: this.category,
          riskLevel: 'MEDIUM',
          title: `${adminDeployers.length} deployer(s) are admin-profile users — SBS-DEP-003`,
          detail:
            'SBS-DEP-003 requires monitoring for unauthorized deployment modifications. Deployments performed by administrator-profile users are harder to distinguish from emergency break-glass changes and are more likely to occur outside of a change-management window.',
          remediation:
            'Replace admin-user deployments with a CI/CD pipeline using a dedicated integration user with only deployment-required permissions. Reserve individual admin accounts for emergency use only, and document any emergency deployments in the system of record.',
          affectedItems: adminDeployers.map(({ username, profile, count }) => ({
            label: username,
            url: auditUrl,
            note: `${count} deployment action(s) | profile: ${profile} — replace with dedicated deployment service account`,
          })),
        });
      }
    }

    return { findings };
  }
}
