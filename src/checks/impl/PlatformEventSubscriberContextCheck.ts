import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface EntityDefinitionRecord {
  DurableId: string;
  QualifiedApiName: string;
}

interface PermissionSetRecord {
  Id: string;
  ProfileId: string;
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

export class PlatformEventSubscriberContextCheck implements SecurityCheck {
  readonly id = 'platform-event-subscriber-context';
  readonly name = 'Platform Event Subscriber Context & Privilege Escalation';
  readonly category = 'Code Security';
  readonly description =
    'Detects Platform Event subscribers executing in system context or as Admin while low-trust or guest users hold Publish permissions.';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // ApexTrigger exists in every org, so a failure here is never "feature absent". It propagates
    // and CheckEngine reports the check as inconclusive.
    const triggers = await ctx.tooling.query<ApexTriggerRecord>(
      "SELECT Id, Name, TableEnumOrId, Status FROM ApexTrigger WHERE Status = 'Active'",
    );

    // TableEnumOrId holds a standard object's name, but a custom object's (and so every custom
    // platform event's) 01I Id. Resolve Ids to API names before testing for the __e suffix.
    const ids = [...new Set(triggers.map((t) => t.TableEnumOrId).filter((v) => !v.includes('_') && v.startsWith('01I')))];
    const nameById = new Map<string, string>();
    if (ids.length > 0) {
      const defs = await ctx.tooling.query<EntityDefinitionRecord>(
        `SELECT DurableId, QualifiedApiName FROM EntityDefinition WHERE DurableId IN (${ids.map((i) => `'${i.slice(0, 15)}'`).join(', ')})`,
      );
      for (const d of defs) nameById.set(d.DurableId.slice(0, 15), d.QualifiedApiName);
    }
    const objectName = (t: ApexTriggerRecord): string => nameById.get(t.TableEnumOrId.slice(0, 15)) ?? t.TableEnumOrId;
    const eventTriggers = triggers.filter((t) => objectName(t).endsWith('__e'));

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

    // Low-trust profiles (guest, portal, Experience Cloud) holding Create on a subscribed event.
    // ObjectPermissions.ParentId is a PermissionSet Id, so each profile is reached through the
    // permission set it owns.
    const eventObjectNames = new Set(eventTriggers.map(objectName));
    const lowTrustProfilesWithCreate: string[] = [];
    const profiles = await ctx.soql.queryAll<ProfileRecord>(
      "SELECT Id, Name, UserType FROM Profile WHERE UserType IN ('Guest', 'CspLitePortal', 'PowerPartner', 'CustomerSuccess', 'PowerCustomerSuccess')",
    );
    if (profiles.length > 0) {
      const profileNameById = new Map(profiles.map((p) => [p.Id, p.Name]));
      const owned = await ctx.soql.queryAll<PermissionSetRecord>(
        `SELECT Id, ProfileId FROM PermissionSet WHERE IsOwnedByProfile = true AND ProfileId IN (${profiles.map((p) => `'${p.Id}'`).join(', ')})`,
      );
      const profileByPermSet = new Map(owned.map((ps) => [ps.Id, ps.ProfileId]));
      // SobjectType does not accept LIKE ("invalid operator on id field"): select these profiles'
      // Create grants and keep the platform events (__e) in code.
      const objectPerms =
        owned.length === 0
          ? []
          : await ctx.soql.queryAll<ObjectPermissionRecord>(
              `SELECT Id, ParentId, SobjectType, PermissionsCreate FROM ObjectPermissions WHERE PermissionsCreate = true AND ParentId IN (${owned.map((ps) => `'${ps.Id}'`).join(', ')})`,
            );
      for (const op of objectPerms) {
        const profileId = profileByPermSet.get(op.ParentId);
        if (profileId && eventObjectNames.has(op.SobjectType)) {
          lowTrustProfilesWithCreate.push(`${op.SobjectType} (${profileNameById.get(profileId) ?? profileId})`);
        }
      }
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
