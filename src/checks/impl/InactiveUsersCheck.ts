import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface InactiveUserRecord {
  Id: string;
  Username: string;
  Name: string;
  LastLoginDate: string | null;
  UserType: string;
  Profile: { Name: string };
}

const BASE_FILTER = `
  IsActive = true
  AND Id NOT IN (SELECT UserId FROM UserLogin WHERE IsFrozen = true)
  AND (LastLoginDate < LAST_N_DAYS:90 OR LastLoginDate = null)
  AND UserType = 'Standard'
`.trim();

export class InactiveUsersCheck implements SecurityCheck {
  readonly id = 'inactive-users';
  readonly name = 'Inactive Users';
  readonly category = 'Users & Admins';
  readonly description = 'Finds active licensed users with no login in the past 90 days';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;

    // Q1: true count — query with LIMIT returns totalSize = min(actual, LIMIT),
    // so a separate COUNT query is required for an accurate number.
    const countResult = await ctx.soql.query<{ expr0: number }>(
      `SELECT COUNT(Id) expr0 FROM User WHERE ${BASE_FILTER}`
    );
    const totalCount = countResult.records[0]?.expr0 ?? 0;

    if (totalCount === 0) {
      findings.push({
        id: 'inactive-users-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active users with 90+ days of inactivity',
        detail: 'All active standard users have logged in within the past 90 days.',
        remediation: 'Continue to run periodic user access reviews to catch future stale accounts.',
      });
      return {
        findings,
        metrics: { inactiveUsers90d: 0 },
      };
    }

    // Q2: fetch up to 50 for the affected-items list (display cap, not count cap)
    const displayUsers = await ctx.soql.queryAll<InactiveUserRecord>(
      `SELECT Id, Username, Name, Profile.Name, LastLoginDate, UserType
       FROM User
       WHERE ${BASE_FILTER}
       ORDER BY LastLoginDate ASC
       LIMIT 50`
    );

    let riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' = 'LOW';
    if (totalCount > 20) {
      riskLevel = 'HIGH';
    } else if (totalCount > 10) {
      riskLevel = 'MEDIUM';
    }

    const overflowNote = totalCount > 50 ? ` (showing first 50 of ${totalCount})` : '';

    findings.push({
      id: 'inactive-users-90d',
      category: this.category,
      riskLevel,
      title: `${totalCount} active user(s) have not logged in for 90+ days`,
      detail: 'Active accounts with no recent login represent stale credentials that may be compromised without detection.',
      remediation: 'Deactivate or review accounts that have been inactive for 90+ days. Establish a regular user access review process.',
      affectedItems: displayUsers.map((u) => ({
        label: `${u.Username} (${u.Name})`,
        url: `${baseUrl}/${u.Id}`,
        note: `Last login: ${u.LastLoginDate ? new Date(u.LastLoginDate).toISOString().split('T')[0] : 'never'}${overflowNote}`,
      })),
    });

    return {
      findings,
      metrics: { inactiveUsers90d: totalCount },
    };
  }
}
