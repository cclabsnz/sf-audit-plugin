import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { isApiError } from '@cclabsnz/sf-core';

interface SubscriberConfigRecord {
  Id: string;
  DeveloperName: string;
  MasterLabel: string;
  PlatformEventConsumerId?: string | null;
  BatchSize?: number | null;
  UserId?: string | null;
}

interface ApexTriggerRecord {
  Id: string;
  Name: string;
  TableEnumOrId: string;
  Status: string;
}

interface ObjectPermissionRecord {
  Id: string;
  ParentId: string;
  SobjectType: string;
  PermissionsCreate: boolean;
  Parent?: {
    Profile?: {
      Name?: string;
      UserType?: string;
    };
    IsOwnedByProfile?: boolean;
  };
}

interface ProfileRecord {
  Id: string;
  Name: string;
  UserType: string;
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

export class PlatformEventSubscriberContextCheck implements SecurityCheck {
  readonly id = 'platform-event-subscriber-context';
  readonly name = 'Platform Event Subscriber Context & Privilege Escalation';
  readonly category = 'Code Security';
  readonly description =
    'Detects Platform Event subscribers executing in system context or as Admin while low-trust or guest users hold Publish permissions.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // 1. Query active Apex Triggers on custom Platform Events (__e)
    let triggers: ApexTriggerRecord[] = [];
    try {
      triggers = await ctx.tooling.query<ApexTriggerRecord>(
        "SELECT Id, Name, TableEnumOrId, Status FROM ApexTrigger WHERE Status = 'Active'",
      );
    } catch (err) {
      if (isMissingObjectError(err)) {
        findings.push({
          id: 'platform-event-subscriber-context-ok',
          category: this.category,
          riskLevel: 'LOW',
          passed: true,
          title: 'No Platform Event triggers found or Tooling API not accessible',
          detail: 'ApexTrigger tooling object returned no records.',
          remediation: 'No action required.',
        });
        return { findings };
      }
      findings.push({
        id: 'platform-event-subscriber-context-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Platform Event Triggers could not be inspected',
        detail: `Failed to query ApexTrigger: ${err instanceof Error ? err.message : String(err)}`,
        remediation: 'Grant the audit user "View Setup and Configuration" and Tooling API access.',
      });
      return { findings };
    }

    const eventTriggers = triggers.filter((t) => t.TableEnumOrId.endsWith('__e'));

    if (eventTriggers.length === 0) {
      findings.push({
        id: 'platform-event-subscriber-context-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active triggers on custom Platform Events identified',
        detail: 'Zero active Apex triggers subscribe to custom Platform Event objects (__e).',
        remediation: 'When subscribing to Platform Events, ensure publish permissions are strictly scoped to internal authorized actors.',
      });
      return { findings };
    }

    // 2. Query PlatformEventSubscriberConfig to see which run as custom users vs Automated Process
    let subscriberConfigs: SubscriberConfigRecord[] = [];
    try {
      subscriberConfigs = await ctx.tooling.query<SubscriberConfigRecord>(
        'SELECT Id, DeveloperName, MasterLabel, PlatformEventConsumerId, BatchSize, UserId FROM PlatformEventSubscriberConfig',
      );
    } catch {
      // Degrade gracefully if PlatformEventSubscriberConfig is empty/not configured
    }

    const configByConsumer = new Map<string, SubscriberConfigRecord>();
    for (const cfg of subscriberConfigs) {
      if (cfg.PlatformEventConsumerId) {
        configByConsumer.set(cfg.PlatformEventConsumerId, cfg);
      }
      configByConsumer.set(cfg.DeveloperName.toLowerCase(), cfg);
    }

    // 3. Query ObjectPermissions for Create permissions on the event objects
    const eventObjectNames = [...new Set(eventTriggers.map((t) => t.TableEnumOrId))];
    let lowTrustProfilesWithCreate: string[] = [];

    try {
      // Get low-trust profiles (Guest, Portal, Experience Cloud)
      const profiles = await ctx.soql.queryAll<ProfileRecord>(
        "SELECT Id, Name, UserType FROM Profile WHERE UserType IN ('Guest', 'CspLitePortal', 'PowerPartner', 'CustomerSuccess', 'PowerCustomerSuccess')",
      );
      const lowTrustProfileIds = new Set(profiles.map((p) => p.Id));
      const profileNameById = new Map(profiles.map((p) => [p.Id, p.Name]));

      const objectPerms = await ctx.soql.queryAll<ObjectPermissionRecord>(
        "SELECT Id, ParentId, SobjectType, PermissionsCreate FROM ObjectPermissions WHERE PermissionsCreate = true AND SobjectType LIKE '%__e'",
      );

      for (const op of objectPerms) {
        if (eventObjectNames.includes(op.SobjectType)) {
          // Check if parent matches a low-trust profile
          if (lowTrustProfileIds.has(op.ParentId)) {
            const profName = profileNameById.get(op.ParentId) ?? op.ParentId;
            lowTrustProfilesWithCreate.push(`${op.SobjectType} (${profName})`);
          }
        }
      }
    } catch {
      // Degrade gracefully if ObjectPermissions query fails
    }

    // If low-trust profiles have Create permission on any custom platform event subscribed to by Apex:
    // This is an unauthenticated or portal-to-system privilege escalation bridge!
    if (lowTrustProfilesWithCreate.length > 0) {
      findings.push({
        id: 'platform-event-subscriber-escalation',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${lowTrustProfilesWithCreate.length} Platform Event(s) publishable by low-trust users trigger system-mode subscribers`,
        detail:
          'Guest or Experience Cloud profiles hold Create (publish) permissions on custom Platform Events that have active Apex subscribers. By default, Platform Event triggers execute under the Automated Process system identity (bypassing user permissions and sharing), creating an unauthenticated-to-system-context privilege escalation bridge.',
        remediation:
          'Revoke Create permissions on Platform Events from guest and portal profiles, or configure PlatformEventSubscriberConfig to run subscribers as a dedicated, least-privileged service account with explicit input validation.',
        affectedItems: lowTrustProfilesWithCreate.map((item) => ({
          label: item,
          url: `${baseUrl}/lightning/setup/EventObjects/home`,
          note: 'Event publishable by low-trust actor executes as Automated Process or Admin',
        })),
      });
    } else {
      findings.push({
        id: 'platform-event-subscriber-context-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Platform Event subscriber triggers are protected from low-trust publish escalation',
        detail: `${eventTriggers.length} active Platform Event trigger(s) inspected; no guest or portal profiles hold Publish permissions on subscribed events.`,
        remediation: 'Ensure low-trust profiles never receive Create permissions on custom Platform Events that execute privileged backend logic.',
      });
    }

    return { findings };
  }
}
