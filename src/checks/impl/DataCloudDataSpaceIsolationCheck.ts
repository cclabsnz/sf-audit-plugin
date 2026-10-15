import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isMissingObjectError, queryIfPresent } from '../support/missingObject.js';

interface DataSpaceRecord {
  Id: string;
  Name?: string | null;
  Description?: string | null;
}

interface DataShareTargetRecord {
  Id: string;
  Name?: string | null;
  TargetType?: string | null;
  Status?: string | null;
}

interface PermissionAssignmentRecord {
  Id: string;
  AssigneeId: string;
  Assignee?: {
    Username?: string;
    UserType?: string;
    Profile?: { Name?: string };
  };
  PermissionSet?: {
    Name?: string;
    Label?: string;
  };
}

const EXTERNAL_USER_TYPES = new Set(['PowerPartner', 'CustomerSuccess', 'PowerCustomerSuccess', 'CspLitePortal', 'Guest']);

function isDataCloudPermSet(ps: PermissionAssignmentRecord['PermissionSet']): boolean {
  return /datacloud|dataspace|cdp/i.test(`${ps?.Name ?? ''} ${ps?.Label ?? ''}`);
}

export class DataCloudDataSpaceIsolationCheck implements SecurityCheck {
  readonly id = 'data-cloud-data-space-isolation';
  readonly name = 'Data Cloud Data Space Isolation';
  readonly category = 'Data Security';
  readonly description =
    'Flags orgs where external integrations, partner users, or agent users are mapped to the default Data Space, or unconstrained Data Share Targets exist.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let dataSpaces: DataSpaceRecord[];
    try {
      dataSpaces = await ctx.soql.queryAll<DataSpaceRecord>(
        'SELECT Id, Name, Description FROM DataSpace',
      );
    } catch (err) {
      if (isMissingObjectError(err)) {
        findings.push({
          id: 'data-cloud-data-space-not-enabled',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'Data Cloud is not enabled or DataSpace is not configured in this org',
          detail: 'DataSpace object is not available; Data Cloud is not enabled or licensed in this org.',
          remediation: 'No action required if Data Cloud is not deployed.',
        });
        return { findings };
      }
      findings.push({
        id: 'data-cloud-data-space-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Data Cloud Data Spaces could not be read',
        detail: `Query to DataSpace failed: ${err instanceof Error ? err.message : String(err)}`,
        remediation: 'Ensure the audit user has permission to view Data Cloud Data Spaces and configuration.',
      });
      return { findings };
    }

    if (dataSpaces.length === 0) {
      findings.push({
        id: 'data-cloud-data-space-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No Data Cloud Data Spaces found',
        detail: 'Zero DataSpace records exist in this org.',
        remediation: 'Define segmented Data Spaces if Data Cloud is activated in the future.',
      });
      return { findings };
    }

    // Data Cloud names its default data space "default". Only Name is selected, so only Name is read.
    const defaultDataSpace = dataSpaces.find((ds) => (ds.Name ?? '').toLowerCase() === 'default');

    // External, guest or agent users holding a Data Cloud permission set they were assigned
    // directly. A profile's own permission set, or an unrelated one, grants no data space access.
    const assignments = await ctx.soql.queryAll<PermissionAssignmentRecord>(
      "SELECT Id, AssigneeId, Assignee.Username, Assignee.UserType, Assignee.Profile.Name, PermissionSet.Name, PermissionSet.Label FROM PermissionSetAssignment WHERE Assignee.IsActive = true AND PermissionSet.IsOwnedByProfile = false AND (PermissionSet.Name LIKE '%DataCloud%' OR PermissionSet.Name LIKE '%DataSpace%' OR PermissionSet.Name LIKE '%CDP%')",
    );
    const byUser = new Map<string, PermissionAssignmentRecord>();
    for (const a of assignments) {
      const uType = a.Assignee?.UserType ?? '';
      const uname = (a.Assignee?.Username ?? '').toLowerCase();
      const lowTrust = EXTERNAL_USER_TYPES.has(uType) || uname.includes('agent');
      if (lowTrust && isDataCloudPermSet(a.PermissionSet) && !byUser.has(a.AssigneeId)) byUser.set(a.AssigneeId, a);
    }
    const oversharedUsers = [...byUser.values()];

    if (defaultDataSpace && oversharedUsers.length > 0) {
      findings.push({
        id: 'data-cloud-data-space-default-overshared',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${oversharedUsers.length} external, partner, or agent user(s) hold Data Cloud access while the default Data Space is in use`,
        detail:
          'Data Cloud default Data Space flattens standard Salesforce OWD record-level sharing. Exposing the default Data Space to external partner, integration, or agent accounts grants bulk visibility across data lake objects (DLOs) and data model objects (DMOs).',
        remediation:
          'Segment data by creating dedicated Data Spaces with restricted permissions, and map partner and agent users only to their respective segmented spaces.',
        affectedItems: oversharedUsers.map((u) => ({
          label: u.Assignee?.Username ?? u.AssigneeId,
          url: `${baseUrl}/lightning/setup/DataCloudDataSpace/home`,
          note: `UserType: ${u.Assignee?.UserType ?? 'Unknown'}; permission set ${u.PermissionSet?.Label ?? u.PermissionSet?.Name ?? 'unknown'}`,
        })),
      });
    }

    // Query DataShareTarget for unconstrained external data sharing
    const shareTargets = await queryIfPresent(() =>
      ctx.soql.queryAll<DataShareTargetRecord>('SELECT Id, Name, TargetType, Status FROM DataShareTarget'),
    );

    const unconstrainedTargets = shareTargets.filter(
      (t) => (t.Status ?? '').toLowerCase() === 'active',
    );

    if (unconstrainedTargets.length > 0) {
      findings.push({
        id: 'data-cloud-data-share-target-unconstrained',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${unconstrainedTargets.length} active Data Cloud Data Share Target(s) without IP or authentication constraints`,
        detail:
          'External Data Share Targets allow zero-copy outbound sharing to external platforms (Snowflake, AWS S3, BigQuery). Active targets without strict constraints expose bulk customer data outside Salesforce boundaries.',
        remediation:
          'Audit all active Data Share Targets, apply IP restrictions, and verify authentication and encryption configurations.',
        affectedItems: unconstrainedTargets.map((t) => ({
          label: t.Name ?? t.Id,
          url: `${baseUrl}/lightning/setup/DataShare/home`,
          note: `TargetType: ${t.TargetType ?? 'Unknown'}, Status: ${t.Status ?? 'Unknown'}`,
        })),
      });
    }

    if (
      (!defaultDataSpace || oversharedUsers.length === 0) &&
      unconstrainedTargets.length === 0
    ) {
      findings.push({
        id: 'data-cloud-data-space-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Data Cloud Data Spaces and Data Share Targets are properly segmented and isolated',
        detail: `${dataSpaces.length} Data Space(s) inspected; no over-sharing to low-trust identities or unconstrained share targets detected.`,
        remediation: 'Continue enforcing segmented Data Spaces for any new integration or external user.',
      });
    }

    return { findings };
  }
}
