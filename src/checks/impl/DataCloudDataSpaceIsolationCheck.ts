import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isMissingObjectError, queryIfPresent } from '../support/missingObject.js';

interface DataSpaceRecord {
  Id: string;
  Name?: string | null;
  Description?: string | null;
}

// ExtDataShare, API 56.0+: a collection of Data Cloud objects shared with another Data Cloud org
// or a third-party partner. DataShareType Outbound means this org shares it out.
// https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_extdatashare.htm
// There is no DataShareTarget object (the targets are ExtDataShareTarget), and no object exposes
// IP or authentication constraints on a share, so the check reports what exists, not how it is
// protected.
interface ExtDataShareRecord {
  Id: string;
  Name?: string | null;
  DataShareType?: string | null;
  ObjectCount?: number | null;
  DataSpace?: { Name?: string | null } | null;
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
    'Flags external, partner or agent users holding Data Cloud permission sets while a data space named "default" exists, and lists outbound Data Cloud data shares for review.';

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
        riskLevel: 'MEDIUM',
        title: `${oversharedUsers.length} external, partner, or agent user(s) hold a Data Cloud permission set while a "default" data space exists`,
        detail:
          'This is a name-based signal, not a confirmed grant. The check matches permission sets whose name or label contains DataCloud, DataSpace or CDP, and a data space named "default"; it does not read which data spaces each permission set grants. Data Cloud objects are not governed by the org\'s record sharing, so a low-trust user with access to the default data space can see every data lake and data model object in it. Confirm which data spaces these permission sets grant.',
        remediation:
          'Check the data spaces each listed permission set grants. If one grants the default data space, create dedicated data spaces with restricted permissions and assign partner and agent users only to those.',
        affectedItems: oversharedUsers.map((u) => ({
          label: u.Assignee?.Username ?? u.AssigneeId,
          url: `${baseUrl}/lightning/setup/DataCloudDataSpace/home`,
          note: `UserType: ${u.Assignee?.UserType ?? 'Unknown'}; permission set ${u.PermissionSet?.Label ?? u.PermissionSet?.Name ?? 'unknown'}`,
        })),
      });
    }

    // Outbound data shares: Data Cloud objects this org shares with another Data Cloud org or a
    // partner platform. Their existence is authorised configuration, so this is a review item.
    const outboundShares = await queryIfPresent(() =>
      ctx.soql.queryAll<ExtDataShareRecord>(
        "SELECT Id, Name, DataShareType, ObjectCount, DataSpace.Name FROM ExtDataShare WHERE DataShareType = 'Outbound'",
      ),
    );

    if (outboundShares.length > 0) {
      findings.push({
        id: 'data-cloud-outbound-data-shares',
        category: this.category,
        riskLevel: 'INFO',
        title: `${outboundShares.length} outbound Data Cloud data share(s) to review`,
        detail:
          'Outbound data shares make Data Cloud objects available outside this org, to another Data Cloud org or a partner platform such as Snowflake, Redshift, BigQuery or Databricks. The check lists them; it cannot read where each share goes or how its target is secured, so this is not evidence of a misconfiguration.',
        remediation:
          'For each share, confirm it is still needed, that it contains only the objects the recipient should see, and that its data share target points to a platform and account you control.',
        affectedItems: outboundShares.map((s) => ({
          label: s.Name ?? s.Id,
          url: `${baseUrl}/lightning/setup/DataShare/home`,
          note: `objects: ${s.ObjectCount ?? 'unknown'}; data space: ${s.DataSpace?.Name ?? 'unknown'}`,
        })),
      });
    }

    if ((!defaultDataSpace || oversharedUsers.length === 0) && outboundShares.length === 0) {
      findings.push({
        id: 'data-cloud-data-space-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No low-trust Data Cloud access or outbound data shares found',
        detail: `${dataSpaces.length} Data Space(s) inspected; no external, partner or agent user holds a Data Cloud permission set alongside a "default" data space, and no outbound data share exists.`,
        remediation: 'Continue enforcing segmented Data Spaces for any new integration or external user.',
      });
    }

    return { findings };
  }
}
