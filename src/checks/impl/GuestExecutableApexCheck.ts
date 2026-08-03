import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';
import { ApexRepository } from '@cclabsnz/sf-core';

interface GuestUser { Id: string; ProfileId: string; Username: string; }
interface SetupAccess { SetupEntityId: string; ParentId: string; }
interface ApexName { Id: string; Name: string; }

const WITHOUT_SHARING = /\bwithout\s+sharing\b/i;
const WITH_SHARING = /\bwith\s+sharing\b/i;

export class GuestExecutableApexCheck implements SecurityCheck {
  readonly id = 'guest-executable-apex';
  readonly name = 'Guest-Executable Apex';
  readonly category = 'Access Control';
  readonly description =
    'Finds Apex classes that unauthenticated guest profiles can execute, flagging those that run without sharing: the classic unauthenticated data-exfiltration vector';

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
    const bodyByName = new Map(bodies.map((b) => [b.name, b.body]));

    const unprotected: string[] = [];
    const exposed: string[] = [];

    for (const id of classIds) {
      const name = nameById.get(id) ?? id;
      const body = bodyByName.get(name);
      if (body && WITHOUT_SHARING.test(body)) {
        unprotected.push(name);
      } else if (body && !WITH_SHARING.test(body)) {
        // No sharing declaration in a guest-reachable class is also dangerous.
        unprotected.push(name);
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
        title: `${unprotected.length} guest-executable Apex class(es) run without "with sharing"`,
        detail:
          'These Apex classes can be invoked by unauthenticated guest users AND do not enforce record-level sharing. ' +
          'This is the classic Salesforce guest-user exploit chain: an attacker calls the class and reads or writes ' +
          'business data in bulk with no login. Object-level guest permissions do not mitigate this: the class runs in system context.',
        remediation:
          'Add "with sharing" to every guest-reachable Apex class, enforce CRUD/FLS, and remove guest execution access from any class that does not strictly need it.',
        affectedItems: unprotected.map((n) => ({ label: n, url: apexUrl, note: 'Guest-executable + without/with-no sharing: fix immediately' })),
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
