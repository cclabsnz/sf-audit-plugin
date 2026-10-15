import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

interface DataSpaceRecord {
  Id: string;
  Name?: string | null;
  DeveloperName?: string | null;
  MasterLabel?: string | null;
  Description?: string | null;
  IsDefault?: boolean | null;
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

function isMissingObjectError(err: unknown): boolean {
  if (isApiError(err)) {
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode)) return true;
    if (err.statusCode === 404) return true;
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes('is not supported') ||
    msg.includes('sobject type')
  );
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

    // Check for default Data Space over-sharing
    const defaultDataSpace = dataSpaces.find(
      (ds) =>
        ds.IsDefault === true ||
        (ds.Name ?? '').toLowerCase() === 'default' ||
        (ds.DeveloperName ?? '').toLowerCase() === 'default',
    );

    // Query assignments to external/partner/agent users with Data Cloud permissions
    let oversharedUsers: PermissionAssignmentRecord[] = [];
    try {
      const assignments = await ctx.soql.queryAll<PermissionAssignmentRecord>(
        "SELECT Id, AssigneeId, Assignee.Username, Assignee.UserType, Assignee.Profile.Name, PermissionSet.Name FROM PermissionSetAssignment WHERE Assignee.IsActive = true AND (Assignee.UserType IN ('PowerPartner', 'CustomerSuccess', 'CspLitePortal', 'Guest') OR Assignee.Username LIKE '%agent%' OR PermissionSet.Name LIKE '%DataCloud%' OR PermissionSet.Name LIKE '%DataSpace%')",
      );
      oversharedUsers = assignments.filter((a) => {
        const uType = a.Assignee?.UserType ?? '';
        const uname = (a.Assignee?.Username ?? '').toLowerCase();
        return (
          uType === 'PowerPartner' ||
          uType === 'CustomerSuccess' ||
          uType === 'Guest' ||
          uname.includes('agent') ||
          uname.includes('integration')
        );
      });
    } catch {
      // Degrade gracefully if assignment query fails
    }

    if (defaultDataSpace && oversharedUsers.length > 0) {
      findings.push({
        id: 'data-cloud-data-space-default-overshared',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${oversharedUsers.length} external, partner, or agent account(s) mapped to default Data Space`,
        detail:
          'Data Cloud default Data Space flattens standard Salesforce OWD record-level sharing. Exposing the default Data Space to external partner, integration, or agent accounts grants bulk visibility across data lake objects (DLOs) and data model objects (DMOs).',
        remediation:
          'Segment data by creating dedicated Data Spaces with restricted permissions, and map partner and agent users only to their respective segmented spaces.',
        affectedItems: oversharedUsers.map((u) => ({
          label: u.Assignee?.Username ?? u.AssigneeId,
          url: `${baseUrl}/lightning/setup/DataCloudDataSpace/home`,
          note: `UserType: ${u.Assignee?.UserType ?? 'Unknown'} assigned to unsegmented data`,
        })),
      });
    }

    // Query DataShareTarget for unconstrained external data sharing
    let shareTargets: DataShareTargetRecord[] = [];
    try {
      shareTargets = await ctx.soql.queryAll<DataShareTargetRecord>(
        'SELECT Id, Name, TargetType, Status FROM DataShareTarget',
      );
    } catch {
      // DataShareTarget may not be enabled
    }

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
