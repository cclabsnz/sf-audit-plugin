import { isApiError } from '../api/ApiError.js';
import type { EventLogAccess } from '../context/AuditCache.js';

/**
 * Classifies why an `EventLogFile` query failed so callers can tell the two very
 * different "no data" causes apart:
 *   - 'not-enabled'   : Event Monitoring is not licensed/enabled (EventLogFile is
 *                       an unknown/blocked sObject) — the org captures nothing.
 *   - 'no-permission' : the feature is on, but the running audit user lacks the
 *                       "View Event Log Files" permission — logs exist, we can't read them.
 *   - 'unknown'       : could not be attributed to either.
 * Both are BLIND for guest-traffic analysis, but the remediation differs (license
 * vs. grant a permission), so the distinction is worth surfacing.
 */
export function classifyEventLogAccessError(err: unknown): EventLogAccess {
  if (isApiError(err)) {
    if (err.statusCode === 403 || /ACCESS|INSUFFICIENT/i.test(err.errorCode)) return 'no-permission';
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode) || err.statusCode === 404 || err.statusCode === 400) {
      return 'not-enabled';
    }
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  if (msg.includes('insufficient') || msg.includes('permission') || msg.includes('view event log')) return 'no-permission';
  if (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes("sobject type 'eventlogfile'") ||
    msg.includes('not enabled') ||
    msg.includes('licens')
  ) {
    return 'not-enabled';
  }
  return 'unknown';
}
