import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

interface TraceFlagRecord {
  Id: string;
  TracedEntityId: string;
  LogType: string;
  ExpirationDate: string;
  DebugLevel: {
    DeveloperName: string;
    ApexCode: string;
  } | null;
}

const HIGH_DETAIL_LEVELS = new Set(['FINE', 'FINER', 'FINEST']);

export class DebugLogAccessCheck implements SecurityCheck {
  readonly id = 'debug-log-access';
  readonly name = 'Active Debug Log Traces';
  readonly category = 'Security Controls';
  readonly description = 'Identifies active TraceFlag records that capture debug logs, including high-detail traces that expose sensitive field values';

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const baseUrl = ctx.orgInfo.instanceUrl;
    const setupUrl = `${baseUrl}/lightning/setup/ApexDebugLog/home`;

    let traces: TraceFlagRecord[] = [];
    try {
      const result = await ctx.soql.query<TraceFlagRecord>(
        `SELECT Id, TracedEntityId, LogType, ExpirationDate,
                DebugLevel.DeveloperName, DebugLevel.ApexCode
         FROM TraceFlag
         WHERE ExpirationDate >= TODAY
         ORDER BY ExpirationDate ASC
         LIMIT 200`
      );
      traces = result.records;
    } catch {
      findings.push({
        id: 'debug-log-inaccessible',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'TraceFlag records could not be retrieved: active debug traces cannot be verified',
        detail:
          'The TraceFlag object was not accessible. This may indicate the audit user lacks API access or the required permission to manage debug logs.',
        remediation:
          'Grant "Manage Users" or "View All Data" permission to the audit user, or review active debug traces manually in Setup → Debug Logs.',
        affectedItems: [{ label: 'Debug Log Setup', url: setupUrl }],
      });
      return { findings };
    }

    if (traces.length === 0) {
      findings.push({
        id: 'debug-log-none',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No active debug log traces found',
        detail:
          'No active TraceFlag records were found. No users or classes are currently being traced, so no sensitive data is being captured in debug logs.',
        remediation:
          'Continue monitoring. Remove debug traces promptly after troubleshooting sessions complete.',
      });
      return { findings };
    }

    const userDebugTraces = traces.filter((t) => t.LogType === 'USER_DEBUG');
    const highDetailTraces = traces.filter(
      (t) => t.DebugLevel !== null && HIGH_DETAIL_LEVELS.has(t.DebugLevel.ApexCode)
    );

    if (userDebugTraces.length > 0) {
      findings.push({
        id: 'debug-log-active-traces',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${userDebugTraces.length} active USER_DEBUG trace flag(s) are capturing all user activity`,
        detail:
          `In production, active debug traces on users should be reviewed: they capture sensitive field values and are accessible to administrators. USER_DEBUG traces record all DML operations, SOQL queries, and field values for the traced user, including data from sensitive objects such as financial records, PII, and health information. Debug logs are visible to any org admin and are not access-controlled at the record level.`,
        remediation:
          'Remove all USER_DEBUG trace flags that are not actively being used for an approved troubleshooting session. Establish a policy requiring trace flags to be removed within 24 hours of creation. Consider using a dedicated sandbox for debugging rather than production.',
        affectedItems: userDebugTraces.map((t) => ({
          label: t.TracedEntityId,
          url: setupUrl,
          note: `LogType: ${t.LogType} (expires: ${new Date(t.ExpirationDate).toISOString().split('T')[0]}, level: ${t.DebugLevel?.DeveloperName ?? 'unknown'})`,
        })),
      });
    }

    if (highDetailTraces.length > 0) {
      findings.push({
        id: 'debug-log-high-level',
        category: this.category,
        riskLevel: 'MEDIUM',
        title: `${highDetailTraces.length} active trace flag(s) use FINE/FINER/FINEST log level: all variable values are captured`,
        detail:
          `Active traces with ApexCode set to FINE, FINER, or FINEST capture the maximum level of detail, including all variable values at every line of code execution. This includes any field values read or written during the traced session, potentially exposing passwords, tokens, PII, and financial data in the debug log output. In production, active debug traces on users should be reviewed: they capture sensitive field values and are accessible to administrators.`,
        remediation:
          'Reduce log levels to ERROR or WARN for any traces that must remain active. Remove high-detail traces immediately after the debugging session is complete. Never leave FINEST-level traces active in production for extended periods.',
        affectedItems: highDetailTraces.map((t) => ({
          label: t.TracedEntityId,
          url: setupUrl,
          note: `ApexCode level: ${t.DebugLevel?.ApexCode ?? 'unknown'} (expires: ${new Date(t.ExpirationDate).toISOString().split('T')[0]})`,
        })),
      });
    }

    return { findings };
  }
}
