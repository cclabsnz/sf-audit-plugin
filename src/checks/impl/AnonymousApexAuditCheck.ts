import type { AuditContext } from '@cclabsnz/sf-core';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface AnonApexRecord {
  CreatedDate: string;
  CreatedBy: {
    Id: string;
    Username: string;
    Profile: { Name: string } | null;
  };
  Section: string;
  Action: string;
  Display: string;
}

interface UserExecution {
  username: string;
  profile: string;
  count: number;
  latest: string;
}

// SetupAuditTrail.Section cannot be filtered in SOQL, so the 90-day trail is read (bounded) and
// matched here.
const DEV_TOOL_SECTIONS = new Set(['Developer Console', 'Developer Tools', 'IDE', 'Development', 'Workbench']);
const ANON_ACTION = /anon|runAs|executeCode/i;
const MAX_TRAIL_ROWS = 10000;

function isAnonymousExecution(r: AnonApexRecord): boolean {
  return DEV_TOOL_SECTIONS.has(r.Section) || ANON_ACTION.test(r.Action ?? '');
}

function isAdminProfile(profileName: string): boolean {
  const lower = profileName.toLowerCase();
  return lower.includes('admin') || lower.includes('system administrator');
}

export class AnonymousApexAuditCheck implements SecurityCheck {
  readonly id = 'anonymous-apex-audit';
  readonly name = 'Anonymous Apex Execution Audit';
  readonly category = 'Code Security';
  readonly description = 'Detects anonymous Apex execution in the last 90 days via SetupAuditTrail';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const auditTrailUrl = `${baseUrl}/lightning/setup/AuditTrail/home`;

    let records: AnonApexRecord[] = [];
    let truncated = false;
    try {
      const trail = await ctx.soql.queryAll<AnonApexRecord>(
        `SELECT CreatedDate, CreatedBy.Id, CreatedBy.Username, CreatedBy.Profile.Name,
                Section, Action, Display
         FROM SetupAuditTrail
         WHERE CreatedDate > LAST_N_DAYS:90
         ORDER BY CreatedDate DESC
         LIMIT ${MAX_TRAIL_ROWS}`
      );
      truncated = trail.length >= MAX_TRAIL_ROWS;
      records = trail.filter(isAnonymousExecution);
    } catch (err) {
      findings.push({
        id: 'anonymous-apex-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'SetupAuditTrail could not be queried: anonymous Apex execution cannot be verified',
        detail:
          `The SetupAuditTrail query failed: ${err instanceof Error ? err.message : String(err)}. If the org denied access, the audit user may lack "View Setup and Configuration".`,
        remediation:
          'Grant "View Setup and Configuration" permission to the audit user. Review anonymous Apex execution manually in Setup → Audit Trail.',
        affectedItems: [{ label: 'Setup Audit Trail', url: auditTrailUrl }],
      });
      return { findings };
    }

    if (records.length === 0 && truncated) {
      findings.push({
        id: 'anonymous-apex-partial',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: `No anonymous Apex execution in the latest ${MAX_TRAIL_ROWS} audit-trail entries; older entries were not read`,
        detail:
          `The 90-day Setup Audit Trail holds more than ${MAX_TRAIL_ROWS} entries, so only the most recent were checked. None of them record anonymous Apex execution, but older ones in the window may.`,
        remediation: 'Review anonymous Apex execution in Setup → Audit Trail, or export the full trail for review.',
        affectedItems: [{ label: 'Setup Audit Trail', url: auditTrailUrl }],
      });
      return { findings };
    }

    if (records.length === 0) {
      findings.push({
        id: 'anonymous-apex-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No anonymous Apex execution detected in the last 90 days',
        detail:
          'No SetupAuditTrail entries matching anonymous Apex execution patterns were found in the last 90 days. This indicates the Developer Console and anonymous Apex execution have not been used recently in production.',
        remediation:
          'Continue monitoring. If anonymous Apex execution is ever required, ensure it is pre-approved, logged, and reviewed.',
      });
      return { findings };
    }

    if (truncated) {
      // Matches were found, but older entries in the window were not read: the list may be short.
      findings.push({
        id: 'anonymous-apex-partial',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: `Anonymous Apex executions listed may be incomplete: only the latest ${MAX_TRAIL_ROWS} audit-trail entries were read`,
        detail: `The 90-day Setup Audit Trail holds more than ${MAX_TRAIL_ROWS} entries. The executions reported here come from the most recent ones; older executions in the window, and the users behind them, may be missing.`,
        remediation: 'Review anonymous Apex execution in Setup → Audit Trail, or export the full trail for review.',
        affectedItems: [{ label: 'Setup Audit Trail', url: auditTrailUrl }],
      });
    }

    const userMap = new Map<string, UserExecution>();
    for (const r of records) {
      const userId = r.CreatedBy.Id;
      const existing = userMap.get(userId);
      const profileName = r.CreatedBy.Profile?.Name ?? 'Unknown';
      if (existing) {
        existing.count += 1;
        if (r.CreatedDate > existing.latest) existing.latest = r.CreatedDate;
      } else {
        userMap.set(userId, {
          username: r.CreatedBy.Username,
          profile: profileName,
          count: 1,
          latest: r.CreatedDate,
        });
      }
    }

    const nonAdminUsers = [...userMap.values()].filter((u) => !isAdminProfile(u.profile));
    const adminOnlyUsers = [...userMap.values()].filter((u) => isAdminProfile(u.profile));

    if (nonAdminUsers.length > 0) {
      findings.push({
        id: 'anonymous-apex-executed',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${nonAdminUsers.length} non-admin user(s) executed anonymous Apex in the last 90 days`,
        detail:
          'Anonymous Apex execution in production is a privileged, hard-to-audit operation. Anon Apex runs as the executing user but leaves no code artifact. It cannot be reviewed, versioned, or rolled back. Non-admin users executing anonymous Apex indicates a significant control gap: these users have Developer Console access in production and can manipulate data or bypass sharing rules without leaving a traceable code change.',
        remediation:
          'Remove Developer Console access from non-admin users. Revoke the "Author Apex" permission from all profiles and permission sets that do not require it. All code changes in production must go through a formal deployment process (change sets, Salesforce DX). Review each execution instance to determine what code was run and what data was affected.',
        affectedItems: nonAdminUsers.map((u) => ({
          label: u.username,
          url: auditTrailUrl,
          note: `${u.count} execution(s). Latest: ${new Date(u.latest).toISOString().split('T')[0]}. Profile: ${u.profile}`,
        })),
      });
    }

    if (adminOnlyUsers.length > 0) {
      findings.push({
        id: 'anonymous-apex-admin-only',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `Anonymous Apex executed by ${adminOnlyUsers.length} admin-profile user(s) in the last 90 days: monitoring recommended`,
        detail:
          'Anonymous Apex execution by administrator-profile users still represents a risk in production: it bypasses change management, leaves no deployable artifact, and cannot be peer-reviewed. Even legitimate use by admins should be tracked, approved, and documented as part of a change management process.',
        remediation:
          'Establish a policy requiring pre-approval for any anonymous Apex execution in production. Log approvals in your change management system. Prefer metadata deployments over anonymous Apex for all production data or configuration changes. Consider restricting Developer Console to a dedicated integration user only.',
        affectedItems: adminOnlyUsers.map((u) => ({
          label: u.username,
          url: auditTrailUrl,
          note: `${u.count} execution(s). Latest: ${new Date(u.latest).toISOString().split('T')[0]}. Profile: ${u.profile}`,
        })),
      });
    }

    return { findings };
  }
}
