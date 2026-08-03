import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import type { AgentUser } from '@cclabsnz/sf-core';

// One PermissionSet row, queried for the system permissions that define admin-equivalent
// blast radius. Field names are PermissionSet.Permissions* API names (same vocabulary as
// permCatalog); an invalid field would fail the whole query with INVALID_FIELD.
interface PermissionSetRow {
  Id: string;
  Label: string;
  PermissionsModifyAllData: boolean;
  PermissionsViewAllData: boolean;
}

// One ObjectPermissions row: the CRUD grant of a permission set on one sObject.
interface ObjectPermissionRow {
  ParentId: string;
  SobjectType: string;
  PermissionsRead: boolean;
  PermissionsCreate: boolean;
  PermissionsEdit: boolean;
  PermissionsDelete: boolean;
}

// Aggregate count of classified fields per object (Data Classification / ComplianceGroup),
// same shape/query DataClassificationCheck uses.
interface FieldClassificationRow {
  objectName: string;
  classifiedCount: number;
}

// An agent user's write access is "broad" when it can create/update/delete on more than
// this many objects. Chosen to match DataClassificationCheck's small-key-object set size
// (7 key objects) with headroom: a legitimate task-scoped agent user should touch only a
// handful of objects, so >10 is a signal of over-provisioning.
const BROAD_WRITE_OBJECT_THRESHOLD = 10;

export class AgentUserPrivilegeCheck implements SecurityCheck {
  readonly id = 'agent-user-privilege';
  readonly name = 'Agent User Privilege';
  readonly category = 'AI & Agents';
  readonly description =
    'Flags Agentforce run-as / agent users whose effective access is over-broad: Modify/View All Data, write access to many objects, or read access to data classified as sensitive. An injected prompt can exfiltrate or mutate exactly what the agent user can reach.';

  readonly dependsOnCache = ['agentUsers', 'agentAccess'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Gate: only run when AgentInventoryCheck confirmed the agent queries succeeded.
    if (ctx.cache.agentAccess !== 'ok') return { findings };

    const agentUsers = ctx.cache.agentUsers ?? [];
    if (agentUsers.length === 0) return { findings };

    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/PermSets/home`;

    // Collect every permission set assigned to any agent user, then query the two
    // permission surfaces once for the whole set (not per user).
    const allPsIds = [...new Set(agentUsers.flatMap((u) => u.permissionSetIds))];
    if (allPsIds.length === 0) return { findings };

    const psIn = allPsIds.map((id) => `'${id}'`).join(', ');

    // System permissions (ModifyAllData / ViewAllData) per permission set.
    let systemPerms: PermissionSetRow[];
    try {
      systemPerms = await ctx.soql.queryAll<PermissionSetRow>(
        `SELECT Id, Label, PermissionsModifyAllData, PermissionsViewAllData
         FROM PermissionSet
         WHERE Id IN (${psIn})`,
      );
    } catch (err) {
      findings.push({
        id: 'agent-user-privilege-inconclusive',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Agent user permissions could not be resolved',
        detail: `The PermissionSet query for agent users was not accessible: ${
          err instanceof Error ? err.message : String(err)
        }`,
        remediation:
          'Grant the audit user "View Setup and Configuration", then re-run the audit.',
      });
      return { findings };
    }

    // Object-level CRUD per permission set. A failure here is non-fatal — we still report
    // the system-permission findings.
    let objectPerms: ObjectPermissionRow[] = [];
    let objectPermsFailed = false;
    try {
      objectPerms = await ctx.soql.queryAll<ObjectPermissionRow>(
        `SELECT ParentId, SobjectType, PermissionsRead, PermissionsCreate, PermissionsEdit, PermissionsDelete
         FROM ObjectPermissions
         WHERE ParentId IN (${psIn})`,
      );
    } catch {
      objectPermsFailed = true;
    }

    // Sensitive objects = objects with at least one classified field (ComplianceGroup set).
    // Query once for every readable object across the agent users; skip the sub-signal
    // silently if the org has no classification data or the Tooling query is unavailable.
    const readableObjects = [
      ...new Set(objectPerms.filter((p) => p.PermissionsRead).map((p) => p.SobjectType)),
    ];
    const sensitiveObjects = await this.querySensitiveObjects(ctx, readableObjects);

    // Index permission-set metadata by id for per-user attribution.
    const psById = new Map(systemPerms.map((p) => [p.Id, p]));
    const objPermsByPs = new Map<string, ObjectPermissionRow[]>();
    for (const op of objectPerms) {
      const list = objPermsByPs.get(op.ParentId) ?? [];
      list.push(op);
      objPermsByPs.set(op.ParentId, list);
    }

    for (const u of agentUsers) {
      this.evaluateUser(u, psById, objPermsByPs, sensitiveObjects, {
        findings,
        setupUrl,
        objectPermsFailed,
      });
    }

    return { findings };
  }

  private evaluateUser(
    u: AgentUser,
    psById: Map<string, PermissionSetRow>,
    objPermsByPs: Map<string, ObjectPermissionRow[]>,
    sensitiveObjects: Set<string>,
    out: { findings: Finding[]; setupUrl: string; objectPermsFailed: boolean },
  ): void {
    const { findings, setupUrl } = out;

    // Which of the user's permission sets grant ModifyAllData / ViewAllData.
    const adminPsLabels: string[] = [];
    let hasModifyAll = false;
    let hasViewAll = false;
    for (const psId of u.permissionSetIds) {
      const ps = psById.get(psId);
      if (!ps) continue;
      if (ps.PermissionsModifyAllData) {
        hasModifyAll = true;
        adminPsLabels.push(`${ps.Label} (Modify All Data)`);
      } else if (ps.PermissionsViewAllData) {
        hasViewAll = true;
        adminPsLabels.push(`${ps.Label} (View All Data)`);
      }
    }

    if (hasModifyAll || hasViewAll) {
      const which = hasModifyAll ? 'Modify All Data' : 'View All Data';
      findings.push({
        id: `agent-user-privilege-admin-${u.userId}`,
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `Agent user ${u.username} holds ${which}`,
        detail:
          `The agent user "${u.username}" (profile ${u.profileName || 'unknown'}) effectively holds ` +
          `${which}, which bypasses sharing across the entire org. Because an Agentforce agent runs as ` +
          `this user, a successful prompt injection inherits ${which.toLowerCase()}: it can ` +
          `${hasModifyAll ? 'read, edit, and delete' : 'read'} every record in the org. This is the ` +
          `worst-case blast radius for an exposed agent.`,
        remediation:
          `Remove ${which} from the offending permission set(s) unless the agent genuinely requires ` +
          `org-wide access. Scope the agent user to only the objects and records its topics need.`,
        affectedItems: [
          {
            label: u.username,
            url: setupUrl,
            note: `Permission set(s): ${adminPsLabels.join(', ')}`,
          },
        ],
      });
    }

    // Broad object write access: union of objects this user can create/update/delete across
    // all of their permission sets.
    const writableObjects = new Set<string>();
    const readableObjects = new Set<string>();
    for (const psId of u.permissionSetIds) {
      for (const op of objPermsByPs.get(psId) ?? []) {
        if (op.PermissionsCreate || op.PermissionsEdit || op.PermissionsDelete) {
          writableObjects.add(op.SobjectType);
        }
        if (op.PermissionsRead) readableObjects.add(op.SobjectType);
      }
    }

    if (writableObjects.size > BROAD_WRITE_OBJECT_THRESHOLD) {
      const objList = [...writableObjects].sort();
      findings.push({
        id: `agent-user-privilege-broad-write-${u.userId}`,
        category: this.category,
        riskLevel: 'HIGH',
        title: `Agent user ${u.username} has write access to ${writableObjects.size} objects`,
        detail:
          `The agent user "${u.username}" can create, update, or delete records on ${writableObjects.size} ` +
          `objects (threshold ${BROAD_WRITE_OBJECT_THRESHOLD}). An injected prompt runs with this write ` +
          `surface, so it could mutate or destroy data across all of them. Objects: ` +
          `${objList.slice(0, 20).join(', ')}${objList.length > 20 ? `, and ${objList.length - 20} more` : ''}.`,
        remediation:
          'Narrow the agent user\'s object CRUD to only the objects its topics act on. Prefer read-only access ' +
          'where the agent only needs to answer questions, and move write actions behind explicit, reviewed Apex/Flow.',
        affectedItems: [
          {
            label: u.username,
            url: setupUrl,
            note: `${writableObjects.size} writable object(s) via permission set(s): ${u.permissionSetIds.join(', ')}`,
          },
        ],
      });
    }

    // Read access to sensitive/classified objects. Silent when the org has no classification
    // data (sensitiveObjects is empty).
    const sensitiveReadable = [...readableObjects].filter((o) => sensitiveObjects.has(o)).sort();
    if (sensitiveReadable.length > 0) {
      findings.push({
        id: `agent-user-privilege-sensitive-read-${u.userId}`,
        category: this.category,
        riskLevel: 'HIGH',
        title: `Agent user ${u.username} can read ${sensitiveReadable.length} object(s) classified as sensitive`,
        detail:
          `The agent user "${u.username}" has read access to ${sensitiveReadable.length} object(s) that carry ` +
          `Data Classification / Compliance Group markings (PII, PCI, HIPAA, GDPR, etc.): ` +
          `${sensitiveReadable.join(', ')}. An injected prompt can exfiltrate exactly this classified data ` +
          `through whatever channel the agent is exposed on.`,
        remediation:
          'Confirm the agent legitimately needs to read these sensitive objects. If not, remove read access. ' +
          'Where it is required, ensure the agent\'s output channels are internal-only and monitored.',
        affectedItems: sensitiveReadable.map((o) => ({
          label: o,
          note: 'read access, object has classified (sensitive) fields',
        })),
      });
    }
  }

  // Objects that have at least one classified field. Reuses DataClassificationCheck's
  // FieldDefinition/ComplianceGroup query, scoped to the objects the agent users can read.
  // Returns an empty set (sub-signal silently skipped) if there is no classification data
  // or the Tooling query is unavailable.
  private async querySensitiveObjects(
    ctx: AuditContext,
    readableObjects: string[],
  ): Promise<Set<string>> {
    if (readableObjects.length === 0) return new Set();
    const objList = readableObjects.map((o) => `'${o}'`).join(', ');
    try {
      const rows = await ctx.tooling.query<FieldClassificationRow>(
        `SELECT EntityDefinition.QualifiedApiName objectName, COUNT(Id) classifiedCount
         FROM FieldDefinition
         WHERE EntityDefinition.QualifiedApiName IN (${objList})
           AND ComplianceGroup != null
         GROUP BY EntityDefinition.QualifiedApiName`,
      );
      return new Set(rows.filter((r) => (r.classifiedCount ?? 0) > 0).map((r) => r.objectName));
    } catch {
      // No classification feature / no Tooling access: skip the sub-signal silently.
      return new Set();
    }
  }
}
