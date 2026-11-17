import type { AuditContext } from '@cclabsnz/sf-core';
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

// SBS-CODE-004: sensitive values passed to System.debug. A term counts only as a whole identifier
// or as one camelCase / underscore word of an identifier in the call's arguments, with string
// literals removed first. Substring matching flagged 'Token refreshed' (a literal) and doBulk
// ("dob" inside a longer word). Each entry is a run of consecutive words.
const SENSITIVE_WORD_RUNS: readonly (readonly string[])[] = [
  ['password'], ['passwd'], ['secret'], ['token'], ['credential'], ['credentials'],
  ['api', 'key'], ['apikey'], ['ssn'], ['dob'], ['date', 'of', 'birth'], ['dateofbirth'],
  ['credit', 'card'], ['creditcard'], ['card', 'number'], ['cardnumber'],
  ['session', 'id'], ['sessionid'], ['pwd'], ['birthdate'], ['birth', 'date'], ['social', 'security'],
  // New Zealand identifiers: National Health Index and IRD numbers.
  ['nhi'], ['ird', 'number'],
];
// One-word terms also match as the end of a lower-case compound such as accesstoken or getpassword.
const SUFFIX_TERMS = ['password', 'passwd', 'secret', 'token', 'credential', 'apikey', 'sessionid'];

/** Apex with // and /* *\/ comments removed, leaving string literals intact. */
function stripComments(body: string): string {
  let out = '';
  let quote: string | null = null;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (quote) {
      out += ch;
      if (ch === '\\') out += body[++i] ?? '';
      else if (ch === quote) quote = null;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      out += ch;
    } else if (ch === '/' && body[i + 1] === '/') {
      while (i < body.length && body[i] !== '\n') i++;
      out += '\n';
    } else if (ch === '/' && body[i + 1] === '*') {
      const end = body.indexOf('*/', i + 2);
      i = end === -1 ? body.length : end + 1;
      out += ' ';
    } else out += ch;
  }
  return out;
}

/** The argument text of every System.debug( ... ) call, matching nested parentheses. */
function debugArguments(body: string): string[] {
  const out: string[] = [];
  const re = /\bSystem\.debug\s*\(/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    let depth = 1;
    let i = m.index + m[0].length;
    let quote: string | null = null;
    const start = i;
    for (; i < body.length && depth > 0; i++) {
      const ch = body[i];
      if (quote) {
        if (ch === '\\') i++;
        else if (ch === quote) quote = null;
      } else if (ch === "'" || ch === '"') quote = ch;
      else if (ch === '(') depth++;
      else if (ch === ')') depth--;
    }
    out.push(body.slice(start, i - 1));
  }
  return out;
}

/** Lower-case words of each identifier, split on underscores and camelCase. */
function identifierWords(args: string): string[][] {
  const code = args.replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"/g, ' ');
  return (code.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []).map((id) =>
    id
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
      .split(/[\s_]+/)
      .filter(Boolean)
      .map((w) => w.toLowerCase()),
  );
}

// The last word of a run may be plural (tokens, passwords).
function containsRun(words: string[], run: readonly string[]): boolean {
  for (let i = 0; i + run.length <= words.length; i++) {
    if (run.every((w, j) => words[i + j] === w || (j === run.length - 1 && words[i + j] === `${w}s`))) return true;
  }
  return false;
}

const endsWithTerm = (words: string[]): boolean =>
  words.some((w) => SUFFIX_TERMS.some((t) => w.length > t.length && (w.endsWith(t) || w.endsWith(`${t}s`))));

function logsSensitiveValue(body: string): boolean {
  return debugArguments(stripComments(body)).some((args) =>
    identifierWords(args).some((words) => endsWithTerm(words) || SENSITIVE_WORD_RUNS.some((run) => containsRun(words, run))),
  );
}

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
        title: 'Apex class bodies not available: SBS-CODE-003/004 check skipped',
        detail: 'SBS-CODE-003/004 require scanning Apex class bodies for logging patterns. Apex bodies were not available in the audit cache. Ensure HardcodedCredentialsCheck runs before this check.',
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
      if (logsSensitiveValue(body)) {
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
        title: `${persistentLoggerClasses.length} Apex class(es) use a persistent logging framework: SBS-CODE-003`,
        detail: `SBS-CODE-003 requires Apex to use a persistent logging framework rather than transient System.debug calls. ${persistentLoggerClasses.length} class(es) reference a persistent logger. Examples: ${persistentLoggerClasses.slice(0, 5).join(', ')}${persistentLoggerClasses.length > 5 ? ` (+${persistentLoggerClasses.length - 5} more)` : ''}.`,
        remediation: 'Extend persistent logging coverage to all production classes that handle significant business logic or integration operations.',
      });
    }

    if (debugOnlyClasses.length > 0) {
      findings.push({
        id: 'apex-logging-debug-only',
        category: this.category,
        riskLevel: scheduledDebugClasses.length > 0 ? 'MEDIUM' : 'LOW',
        title: `${debugOnlyClasses.length} Apex class(es) use only System.debug: SBS-CODE-003`,
        detail:
          `SBS-CODE-003 requires a persistent logging framework so that audit and error events are durable and searchable after the fact. ${debugOnlyClasses.length} production class(es) rely solely on System.debug, whose output is transient and unavailable once the debug log expires. ${scheduledDebugClasses.length > 0 ? `${scheduledDebugClasses.length} of these are scheduled or batch jobs. Persistent logging is especially important for operational visibility in background processes.` : ''}`,
        remediation:
          'Adopt a persistent logging framework (a custom Log__c object, Platform Events, or an open-source framework) and migrate System.debug calls to it for all classes handling critical business logic.',
        affectedItems: debugOnlyClasses.slice(0, 30).map((name) => ({
          label: name,
          url: apexClassesUrl,
          note: scheduledClassNames.has(name)
            ? 'scheduled/batch job: high priority to add persistent logging'
            : 'System.debug only: no persistent log trail',
        })),
      });
    }

    if (sensitiveLogClasses.length > 0) {
      findings.push({
        id: 'apex-logging-sensitive-data',
        category: this.category,
        // A disclosure, not a repudiation gap: its fix removes logging (RULE-103).
        threats: { stride: ['I'] },
        riskLevel: 'HIGH',
        title: `${sensitiveLogClasses.length} Apex class(es) may log sensitive data: SBS-CODE-004`,
        detail:
          'SBS-CODE-004 prohibits logging sensitive data (passwords, tokens, session IDs, PII) in Apex. The flagged classes appear to pass sensitive variable names or credential values directly to System.debug(), which writes them to debug logs accessible to any administrator who can view debug logs.',
        remediation:
          'Remove all logging of passwords, tokens, API keys, and PII from Apex code. Review each flagged class and mask, redact, or entirely exclude sensitive values before passing them to any logging call.',
        affectedItems: sensitiveLogClasses.map((name) => ({
          label: name,
          url: apexClassesUrl,
          note: 'Review System.debug() calls: sensitive variable names detected near logging statements',
        })),
      });
    }

    if (debugOnlyClasses.length === 0 && sensitiveLogClasses.length === 0 && persistentLoggerClasses.length === 0) {
      findings.push({
        id: 'apex-logging-no-debug',
        category: this.category,
        riskLevel: 'LOW',
        passed: true,
        title: 'No System.debug-only logging or sensitive-data logging patterns found: SBS-CODE-003/004',
        detail: 'SBS-CODE-003 requires a persistent logging framework and SBS-CODE-004 prohibits sensitive data in logs. No violations were detected in the scanned Apex classes.',
        remediation: 'Continue monitoring as new Apex classes are added to the org.',
      });
    }

    return { findings };
  }
}
