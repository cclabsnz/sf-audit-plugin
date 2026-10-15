import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { ApexRepository } from '@cclabsnz/sf-core';
import { declaresWithoutSharing, sharingKeyword, usesSystemMode } from '../support/apexAccess.js';

interface GuestUser { Id: string; ProfileId: string; Username: string; }
interface SetupAccess { SetupEntityId: string; ParentId: string; }

/**
 * The org-local classes a class calls, as its compiled SymbolTable records them. A reference with a
 * namespace is to packaged code, which the audit does not read, so it never resolves to a local
 * class that happens to share its name.
 */
function referencedClasses(symbolTable: unknown): string[] {
  const refs = (symbolTable as { externalReferences?: Array<{ name?: unknown; namespace?: unknown }> } | null | undefined)
    ?.externalReferences;
  if (!Array.isArray(refs)) return [];
  return refs
    .filter((r) => !(typeof r?.namespace === 'string' && r.namespace !== ''))
    .map((r) => r?.name)
    .filter((n): n is string => typeof n === 'string' && n !== '');
}

export class GuestExecutableApexCheck implements SecurityCheck {
  readonly id = 'guest-executable-apex';
  readonly name = 'Guest-Executable Apex';
  readonly category = 'Access Control';
  readonly description =
    'Finds Apex classes that unauthenticated guest profiles can execute, flagging those that run without sharing, call a without-sharing helper, or switch off CRUD/FLS with SYSTEM_MODE';

  // Use cached Apex bodies (from HardcodedCredentialsCheck) when available to classify sharing.
  readonly dependsOnCache = ['apexBodies'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    const guests = await ctx.soql.queryAll<GuestUser>(
      "SELECT Id, ProfileId, Username FROM User WHERE UserType = 'Guest' AND IsActive = true",
    );
    if (guests.length === 0) {
      findings.push({
        id: 'guest-executable-apex-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active guest users: guest-executable Apex not a concern',
        detail: 'There are no active guest users, so no Apex class is reachable by unauthenticated visitors.',
        remediation: 'If an Experience Cloud/Sites guest user is added later, re-run this audit.',
      });
      return { findings };
    }

    const profileIds = [...new Set(guests.map((g) => g.ProfileId))];
    const profileList = profileIds.map((id) => `'${id}'`).join(', ');

    const access = await ctx.soql.queryAll<SetupAccess>(
      `SELECT SetupEntityId, ParentId FROM SetupEntityAccess
       WHERE SetupEntityType = 'ApexClass' AND ParentId IN (${profileList})`,
    );

    const classIds = [...new Set(access.map((a) => a.SetupEntityId))];
    if (classIds.length === 0) {
      findings.push({
        id: 'guest-executable-apex-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'Guest profiles cannot execute any Apex classes',
        detail: 'No Apex class execution access is granted to guest user profiles.',
        remediation: 'Continue to avoid granting Apex class access to guest profiles.',
      });
      return { findings };
    }

    // Ids are validated inside the repository: one malformed value in an IN(...) clause
    // fails the whole query with "invalid ID field", losing every good row with it.
    const nameById = await new ApexRepository(ctx.tooling).namesByIds(classIds);

    const bodies = ctx.cache.apexBodies ?? [];
    // Apex names are case-insensitive, and a SymbolTable may spell one differently from its declaration.
    const byName = new Map(bodies.map((b) => [b.name.toLowerCase(), b]));

    /**
     * Everything reachable from `start` through SymbolTable references: whichever class is declared
     * without sharing, at any depth, runs its own code without sharing (spec RULE-004), and SYSTEM_MODE
     * anywhere on the path lifts CRUD/FLS for the guest (RULE-003).
     */
    const reach = (start: string): { withoutSharing?: string; systemMode?: string } => {
      const seen = new Set([start.toLowerCase()]);
      const queue = referencedClasses(byName.get(start.toLowerCase())?.symbolTable);
      let systemModeAt: string | undefined;
      while (queue.length > 0) {
        const ref = queue.shift()!;
        if (seen.has(ref.toLowerCase())) continue;
        seen.add(ref.toLowerCase());
        const helper = byName.get(ref.toLowerCase());
        if (!helper?.body) continue;
        if (declaresWithoutSharing(helper.body)) return { withoutSharing: helper.name };
        if (!systemModeAt && usesSystemMode(helper.body)) systemModeAt = helper.name;
        queue.push(...referencedClasses(helper.symbolTable));
      }
      return { systemMode: systemModeAt };
    };

    // spec/apex-access-mode.md. A guest call is an entry point: no keyword means without sharing,
    // and inherited sharing means with sharing. SYSTEM_MODE bypasses CRUD/FLS only (RULE-003); a
    // helper declared without sharing bypasses sharing for whatever it does (RULE-004).
    const unprotected: { name: string; note: string }[] = [];
    const systemMode: { name: string; via?: string }[] = [];
    const exposed: string[] = [];

    for (const id of classIds) {
      const name = nameById.get(id) ?? id;
      const entry = byName.get(name.toLowerCase());
      const body = entry?.body;
      const keyword = body ? sharingKeyword(name, body) : null;

      if (keyword === 'without' || (keyword !== null && body && declaresWithoutSharing(body))) {
        unprotected.push({
          name,
          note: keyword === 'without' ? 'Declared "without sharing": fix immediately' : 'Contains an inner class declared "without sharing"',
        });
        continue;
      }
      if (keyword === 'none') {
        unprotected.push({ name, note: 'No sharing declaration: runs without sharing when a guest calls it' });
        continue;
      }
      if (keyword === null || !body) {
        // No readable body (managed or hidden): its sharing cannot be judged.
        exposed.push(name);
        continue;
      }

      const path = reach(name);
      if (path.withoutSharing) {
        unprotected.push({ name, note: `Reaches "${path.withoutSharing}", which is declared "without sharing"` });
      } else if (usesSystemMode(body) || path.systemMode) {
        systemMode.push({ name, via: usesSystemMode(body) ? undefined : path.systemMode });
      } else {
        exposed.push(name);
      }
    }

    const apexUrl = `${baseUrl}/lightning/setup/ApexClasses/home`;

    if (unprotected.length > 0) {
      findings.push({
        id: 'guest-executable-apex-unprotected',
        category: this.category,
        riskLevel: 'CRITICAL',
        title: `${unprotected.length} guest-executable Apex class(es) run without sharing, directly or through a helper`,
        detail:
          'These Apex classes can be invoked by unauthenticated guest users AND do not enforce record-level sharing, ' +
          'either themselves or in a helper class they call that is declared "without sharing". ' +
          'This is the classic Salesforce guest-user exploit chain: an attacker calls the class and reads or writes ' +
          'business data in bulk with no login. Object-level guest permissions do not mitigate this: the class runs in system context.',
        remediation:
          'Add "with sharing" to every guest-reachable Apex class and to every helper it calls, enforce CRUD/FLS, and remove guest execution access from any class that does not strictly need it.',
        affectedItems: unprotected.map((u) => ({ label: u.name, url: apexUrl, note: u.note })),
      });
    }

    if (systemMode.length > 0) {
      findings.push({
        id: 'guest-executable-apex-system-mode',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${systemMode.length} guest-executable Apex class(es) switch off CRUD/FLS with SYSTEM_MODE`,
        detail:
          'Guest users can execute these classes, which enforce sharing but run queries or DML with WITH SYSTEM_MODE or ' +
          'AccessLevel.SYSTEM_MODE. Sharing still limits which records a guest reaches, but not which objects and fields: ' +
          'a guest can read or change fields the guest profile is denied on any record shared with guests.',
        remediation:
          'Replace SYSTEM_MODE with USER_MODE in guest-reachable code, or strip fields with Security.stripInaccessible() before returning results. Remove guest access where unnecessary.',
        affectedItems: systemMode.map(({ name, via }) => ({
          label: name,
          url: apexUrl,
          note: via ? `Calls "${via}", which uses SYSTEM_MODE: guest CRUD/FLS not enforced` : 'SYSTEM_MODE: guest CRUD/FLS not enforced',
        })),
      });
    }

    if (exposed.length > 0) {
      findings.push({
        id: 'guest-executable-apex-exposed',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${exposed.length} Apex class(es) are executable by guest users`,
        detail:
          'Guest user profiles can execute these Apex classes. Even with "with sharing", any guest-reachable Apex is ' +
          'unauthenticated attack surface and must enforce CRUD/FLS and validate all input.',
        remediation:
          'Review each class for least-privilege: confirm "with sharing", CRUD/FLS checks, and input validation. Remove guest access where unnecessary.',
        affectedItems: exposed.map((n) => ({ label: n, url: apexUrl, note: 'Guest-executable: review for least privilege' })),
      });
    }

    return { findings };
  }
}
