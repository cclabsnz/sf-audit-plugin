import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface InactiveUserRecord {
  Username: string;
  Name: string;
  LastLoginDate: string | null;
  UserType: string;
  Profile: { Name: string };
}

export class InactiveUsersCheck implements SecurityCheck {
  readonly id = 'inactive-users';
  readonly name = 'Inactive Users';
  readonly category = 'Users & Admins';
  readonly description = 'Finds active licensed users with no login in the past 90 days';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];

    const inactiveUsers = await ctx.soql.queryAll<InactiveUserRecord>(`
      SELECT Username, Name, Profile.Name, LastLoginDate, UserType 
      FROM User 
      WHERE IsActive = true 
        AND (LastLoginDate < LAST_N_DAYS:90 OR LastLoginDate = null) 
        AND UserType = 'Standard' 
      ORDER BY LastLoginDate ASC 
      LIMIT 50
    `);

    const count = inactiveUsers.length;

    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' = 'LOW';
    if (count > 20) {
      riskLevel = 'HIGH';
    } else if (count > 10) {
      riskLevel = 'MEDIUM';
    }

    const affectedItems = inactiveUsers.map(
      (u: InactiveUserRecord) => `${u.Username} (${u.Name}) — last login: ${u.LastLoginDate ?? 'never'}`
    );

    findings.push({
      id: 'inactive-users-90d',
      category: this.category,
      riskLevel,
      title: `${count} active user(s) have not logged in for 90+ days`,
      detail: 'Active accounts with no recent login represent stale credentials that may be compromised without detection.',
      remediation: 'Deactivate or review accounts that have been inactive for 90+ days. Establish a regular user access review process.',
      affectedItems,
    });

    return {
      findings,
      metrics: {
        inactiveUsers90d: count,
      },
    };
  }
}
