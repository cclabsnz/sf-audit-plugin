import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface PermSetRec {
  Id: string;
  Label: string;
  Type: string;
  Profile: { Name: string } | null;
  PermissionsDataExport: boolean;
  PermissionsApiEnabled: boolean;
  PermissionsViewAllData: boolean;
  PermissionsModifyAllData: boolean;
}

/**
 * Finds the profiles / permission sets that grant a bulk data-extraction
 * capability — the mechanisms an attacker (or a departing insider) uses to
 * exfiltrate en masse, which the report/sharing checks do not cover:
 *   - "Weekly Data Export" (PermissionsDataExport): full-org CSV export.
 *   - "API Enabled" combined with View/Modify All Data: unrestricted Bulk/REST pull
 *     of every record.
 * The toxic combination (export or API + ViewAll) is graded highest.
 */
export class DataExportAccessCheck implements SecurityCheck {
  readonly id = 'data-export-access';
  readonly name = 'Mass Data Export Access';
  readonly category = 'Data Access Control';
  readonly description =
    'Flags profiles/permission sets granting Weekly Data Export or API access combined with View/Modify All Data — the bulk data-exfiltration capability';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    let rows: PermSetRec[];
    try {
      rows = await ctx.soql.queryAll<PermSetRec>(
        `SELECT Id, Label, Type, Profile.Name, PermissionsDataExport, PermissionsApiEnabled,
                PermissionsViewAllData, PermissionsModifyAllData
         FROM PermissionSet
         WHERE PermissionsDataExport = true OR (PermissionsApiEnabled = true AND (PermissionsViewAllData = true OR PermissionsModifyAllData = true))`,
      );
    } catch {
      findings.push({
        id: 'data-export-access-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Data-export permissions could not be queried (insufficient access)',
        detail: 'PermissionSet was not accessible, so mass-export capability could not be evaluated.',
        remediation: 'Grant the audit user access to PermissionSet (View Setup and Configuration) and re-run.',
      });
      return { findings };
    }

    const label = (r: PermSetRec) => (r.Type === 'Profile' && r.Profile ? `Profile: ${r.Profile.Name}` : `Permission Set: ${r.Label}`);
    const exportGrants = rows.filter((r) => r.PermissionsDataExport);
    const bulkApiGrants = rows.filter((r) => r.PermissionsApiEnabled && (r.PermissionsViewAllData || r.PermissionsModifyAllData));

    if (exportGrants.length > 0) {
      findings.push({
        id: 'data-export-weekly-export',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${exportGrants.length} profile(s)/permission set(s) grant "Weekly Data Export"`,
        detail:
          'The "Weekly Data Export" permission lets the holder export the entire org to CSV on demand. Granted beyond a small set of trusted administrators, it is a one-click mass-exfiltration capability with no per-object gating.',
        remediation:
          'Remove "Weekly Data Export" from all but a minimal set of named administrators. Prefer a monitored, purpose-built integration for scheduled extracts, and alert on Data Export events via Event Monitoring.',
        affectedItems: exportGrants.slice(0, 40).map((r) => ({ label: label(r), url: `${baseUrl}/lightning/setup/PermSets/home` })),
      });
    }

    if (bulkApiGrants.length > 0) {
      findings.push({
        id: 'data-export-bulk-api-viewall',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${bulkApiGrants.length} profile(s)/permission set(s) combine API access with View/Modify All Data`,
        detail:
          'API Enabled together with View All Data or Modify All Data lets the holder pull (or alter) every record in the org through the Bulk/REST API from any client — a programmatic bulk-exfiltration path that bypasses UI and sharing.',
        remediation:
          'Split these grants: integration/service accounts should hold API access scoped by object permissions, not View/Modify All. Remove View/Modify All from any account that only needs targeted API access, and restrict API clients via "API Access Control".',
        affectedItems: bulkApiGrants.slice(0, 40).map((r) => ({
          label: `${label(r)}${r.PermissionsModifyAllData ? ' (Modify All)' : ' (View All)'}`,
          url: `${baseUrl}/lightning/setup/PermSets/home`,
        })),
      });
    }

    if (findings.length === 0) {
      findings.push({
        id: 'data-export-access-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No broad mass-export capability found',
        detail: 'No profiles/permission sets grant Weekly Data Export, nor API access combined with View/Modify All Data.',
        remediation: 'Keep Weekly Data Export and View/Modify-All limited to trusted admins, and prefer scoped integration users for extracts.',
      });
    }

    return { findings };
  }
}
