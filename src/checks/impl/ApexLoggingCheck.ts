import type { AuditContext } from '../../context/AuditContext.js';
import type { SecurityCheck, CheckResult } from '../SecurityCheck.js';
import type { Finding } from '../../findings/Finding.js';

// SBS-CODE-003: indicators of a persistent logging framework (as opposed to System.debug)
const PERSISTENT_LOGGER_PATTERNS = [
  /\bfflib_Logger\b/i,
  /\bLogger\s*\.\s*(?:log|info|warn|error|debug|fine)\s*\(/i,
  /\bLoggingService\s*\.\s*(?:log|info|warn|error)\s*\(/i,
  /\bLogService\s*\.\s*(?:log|info|warn|error)\s*\(/i,
  /\bApplicationLogger\b/i,
  /\bPlatformLogger\b/i,
  /EventBus\.publish\s*\(/i,             // logging via Platform Events
  /insert\s+new\s+Log__c\b/i,           // custom log object insert
  /insert\s+logRecords\b/i,
  /\bApplicationLog\s*\.\s*(?:log|add)\b/i,
];

// SBS-CODE-004: patterns suggesting sensitive data is passed to System.debug
const SENSITIVE_LOG_PATTERNS = [
  /System\.debug\s*\([^)]*(?:password|secret|token|apiKey|api_key|credential|ssn|dob|dateOfBirth|creditCard|cardNumber)/i,
  /System\.debug\s*\([^)]*(?:UserInfo\.getSessionId|Auth\.AuthToken|getSessionId\(\))/i,
];

const SYSTEM_DEBUG_RE = /\bSystem\.debug\s*\(/;
const IS_TEST_CLASS_RE = /@IsTest\b/i;

export class ApexLoggingCheck implements SecurityCheck {
  readonly id = 'apex-logging';
  readonly name = 'Apex Logging Framework';
  readonly category = 'Code Security';
  readonly description = 'SBS-CODE-003/004: checks for persistent logging framework usage and sensitive data in Apex logs';

  // Apex bodies are written by HardcodedCredentialsCheck;
  // scheduled class names are written by ScheduledApexCheck.
  readonly dependsOnCache = ['apexBodies', 'scheduledApexClassNames'] as const;

  async run(ctx: AuditContext): Promise<CheckResult> {
    const findings: Finding[] = [];
    const apexClassesUrl = `${ctx.orgInfo.instanceUrl}/lightning/setup/ApexClasses/home`;

    const apexBodies = ctx.cache.apexBodies ?? [];
    const scheduledClassNames = new Set(ctx.cache.scheduledApexClassNames ?? []);

    if (apexBodies.length === 0) {
      findings.push({
        id: 'apex-logging-no-bodies',
        category: this.category,
        riskLevel: 'INFO',
        inconclusive: true,
        title: 'Apex class bodies not available — SBS-CODE-003/004 check skipped',
        detail: 'SBS-CODE-003/004 require scanning Apex class bodies for logging patterns. Apex bodies were not available in the audit cache — ensure HardcodedCredentialsCheck runs before this check.',
        remediation: 'Verify HardcodedCredentialsCheck is registered before ApexLoggingCheck in the check registry.',
      });
      return { findings };
    }

    const productionClasses = apexBodies.filter((c) => c.body && !IS_TEST_CLASS_RE.test(c.body));

    const debugOnlyClasses: string[] = [];
    const persistentLoggerClasses: string[] = [];

    for (const { name, body } of productionClasses) {
      const hasPersistentLogger = PERSISTENT_LOGGER_PATTERNS.some((p) => p.test(body));
      const hasSystemDebug = SYSTEM_DEBUG_RE.test(body);

      if (hasPersistentLogger) {
        persistentLoggerClasses.push(name);
      } else if (hasSystemDebug) {
        debugOnlyClasses.push(name);
      }
    }

    // SBS-CODE-004: flag classes that appear to log sensitive values
    const sensitiveLogClasses: string[] = [];
    for (const { name, body } of productionClasses) {
      if (SENSITIVE_LOG_PATTERNS.some((p) => p.test(body))) {
        sensitiveLogClasses.push(name);
      }
    }

    const scheduledDebugClasses = debugOnlyClasses.filter((n) => scheduledClassNames.has(n));

    if (persistentLoggerClasses.length > 0) {
      findings.push({
        id: 'apex-logging-framework-in-use',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: `${persistentLoggerClasses.length} Apex class(es) use a persistent logging framework — SBS-CODE-003`,
        detail: `SBS-CODE-003 requires Apex to use a persistent logging framework rather than transient System.debug calls. ${persistentLoggerClasses.length} class(es) reference a persistent logger. Examples: ${persistentLoggerClasses.slice(0, 5).join(', ')}${persistentLoggerClasses.length > 5 ? ` (+${persistentLoggerClasses.length - 5} more)` : ''}.`,
        remediation: 'Extend persistent logging coverage to all production classes that handle significant business logic or integration operations.',
      });
    }

    if (debugOnlyClasses.length > 0) {
      findings.push({
        id: 'apex-logging-debug-only',
        category: this.category,
        riskLevel: scheduledDebugClasses.length > 0 ? 'MEDIUM' : 'LOW',
        title: `${debugOnlyClasses.length} Apex class(es) use only System.debug — SBS-CODE-003`,
        detail:
          `SBS-CODE-003 requires a persistent logging framework so that audit and error events are durable and searchable after the fact. ${debugOnlyClasses.length} production class(es) rely solely on System.debug, whose output is transient and unavailable once the debug log expires. ${scheduledDebugClasses.length > 0 ? `${scheduledDebugClasses.length} of these are scheduled or batch jobs — persistent logging is especially important for operational visibility in background processes.` : ''}`,
        remediation:
          'Adopt a persistent logging framework (a custom Log__c object, Platform Events, or an open-source framework) and migrate System.debug calls to it for all classes handling critical business logic.',
        affectedItems: debugOnlyClasses.slice(0, 30).map((name) => ({
          label: name,
          url: apexClassesUrl,
          note: scheduledClassNames.has(name)
            ? 'scheduled/batch job — high priority to add persistent logging'
            : 'System.debug only — no persistent log trail',
        })),
      });
    }

    if (sensitiveLogClasses.length > 0) {
      findings.push({
        id: 'apex-logging-sensitive-data',
        category: this.category,
        riskLevel: 'HIGH',
        title: `${sensitiveLogClasses.length} Apex class(es) may log sensitive data — SBS-CODE-004`,
        detail:
          'SBS-CODE-004 prohibits logging sensitive data (passwords, tokens, session IDs, PII) in Apex. The flagged classes appear to pass sensitive variable names or credential values directly to System.debug(), which writes them to debug logs accessible to any administrator who can view debug logs.',
        remediation:
          'Remove all logging of passwords, tokens, API keys, and PII from Apex code. Review each flagged class and mask, redact, or entirely exclude sensitive values before passing them to any logging call.',
        affectedItems: sensitiveLogClasses.map((name) => ({
          label: name,
          url: apexClassesUrl,
          note: 'Review System.debug() calls — sensitive variable names detected near logging statements',
        })),
      });
    }

    if (debugOnlyClasses.length === 0 && sensitiveLogClasses.length === 0 && persistentLoggerClasses.length === 0) {
      findings.push({
        id: 'apex-logging-no-debug',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No System.debug-only logging or sensitive-data logging patterns found — SBS-CODE-003/004',
        detail: 'SBS-CODE-003 requires a persistent logging framework and SBS-CODE-004 prohibits sensitive data in logs. No violations were detected in the scanned Apex classes.',
        remediation: 'Continue monitoring as new Apex classes are added to the org.',
      });
    }

    return { findings };
  }
}
