import { isApiError } from '@cclabsnz/sf-core';

/**
 * True when a query failed because the object or feature does not exist in this org (an
 * unlicensed cloud, a disabled feature): the evidence is genuinely absent, so the check may
 * treat the result as empty.
 *
 * Anything else, a permission error above all, must be rethrown so CheckEngine reports the
 * check as inconclusive. Swallowing it reads as "nothing found", which a report then states
 * as a pass.
 */
export function isMissingObjectError(err: unknown): boolean {
  if (isApiError(err)) {
    // MALFORMED_QUERY is a bug in the query, never an absent feature: treating it as "no rows"
    // would report an unchecked area as clean.
    if (/INVALID_TYPE|NOT_FOUND/i.test(err.errorCode)) return true;
    // sf-core 0.12: a Connection-path 404 with no Salesforce code carries no statusCode.
    if (err.statusCode === 404 || err.errorCode === 'ERROR_HTTP_404') return true;
  }
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('not supported') ||
    msg.includes('invalid type') ||
    msg.includes('is not supported') ||
    msg.includes('sobject type')
  );
}

/** Run a query, returning [] only when the object does not exist in this org. Other errors propagate. */
export async function queryIfPresent<T>(run: () => Promise<T[]>): Promise<T[]> {
  try {
    return await run();
  } catch (err) {
    if (isMissingObjectError(err)) return [];
    throw err;
  }
}
