import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface ProfileGroupRecord {
  ProfileName: string;
  UserCount: number;
}

interface UserRecord {
  Id: string;
  Username: string;
  Profile: { Name: string };
}

// SBS-ACS-005: "All active users must be assigned custom profiles.
// The out-of-the-box standard profiles must not be used."
const STANDARD_PROFILE_NAMES = [
  'System Administrator', 'Standard User', 'Read Only', 'Solution Manager',
  'Marketing User', 'Contract Manager', 'Standard Platform User',
  'Standard Platform One App User', 'Chatter Free User', 'Chatter External User',
  'Chatter Moderator User', 'High Volume Customer Portal User', 'Authenticated Website',
  'Customer Portal Manager Standard', 'Partner App Subscription User',
  'Analytics Cloud Explorer User', 'Identity User', 'Work.com Only User',
  'Force.com - App Subscription User', 'Force.com - One App User', 'Force.com - Free User',
  'Guest User', 'External Apps Login User', 'External Identity User',
  'Minimum Access - Salesforce',
];

export class StandardProfilesCheck implements SecurityCheck {
  readonly id = 'standard-profiles';
  readonly name = 'Standard Profile Usage';
  readonly category = 'Permissions';
  readonly description = 'SBS-ACS-005: flags active users assigned to out-of-the-box Salesforce standard profiles';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const profileList = STANDARD_PROFILE_NAMES.map((n) => `'${n}'`).join(', ');
    const frozenFilter = 'Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)';

    // Query 1: aggregate count per profile — avoids fetching every user row upfront
    const countResult = await ctx.soql.query<ProfileGroupRecord>(
      `SELECT Profile.Name ProfileName, COUNT(Id) UserCount
       FROM User
       WHERE IsActive = true AND Profile.Name IN (${profileList})
         AND ${frozenFilter}
       GROUP BY Profile.Name`
    );
    const groups = countResult.records;
    const totalAffected = groups.reduce((sum, r) => sum + r.UserCount, 0);

    if (totalAffected === 0) {
      findings.push({
        id: 'standard-profiles-ok',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active users are assigned to standard out-of-the-box Salesforce profiles',
        detail: 'SBS-ACS-005 requires all active users be on custom profiles. No violations found.',
        remediation: 'Continue monitoring as new users are onboarded.',
      });
      return { findings };
    }

    // Query 2: list affected users only when violations exist
    const users = await ctx.soql.queryAll<UserRecord>(
      `SELECT Id, Username, Profile.Name
       FROM User
       WHERE IsActive = true AND Profile.Name IN (${profileList})
         AND ${frozenFilter}
       ORDER BY Profile.Name, Username
       LIMIT 200`
    );

    const profileSummary = groups.map((g) => `${g.ProfileName} (${g.UserCount})`).join(', ');

    findings.push({
      id: 'standard-profiles-in-use',
      category: this.category,
      riskLevel: 'HIGH',
      title: `${totalAffected} active user(s) assigned to standard out-of-the-box Salesforce profiles`,
      detail:
        `SBS-ACS-005 requires all active users be assigned custom profiles: standard profiles must not be used in production. Standard profiles grant broad, poorly-audited permissions and cannot be tailored to least-privilege requirements. Affected profile(s): ${profileSummary}.`,
      remediation:
        'Create custom profiles based on minimum required permissions and migrate all active users. Remove access to standard profiles in production. Standard profiles cannot be edited so they often grant more than needed.',
      affectedItems: users.slice(0, 50).map((u) => ({
        label: u.Username,
        url: `${baseUrl}/${u.Id}`,
        note: `Profile: ${u.Profile.Name}, migrate to a custom profile`,
      })),
    });

    return { findings };
  }
}
