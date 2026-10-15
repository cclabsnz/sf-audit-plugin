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
    if (/INVALID_TYPE|NOT_FOUND|MALFORMED_QUERY/i.test(err.errorCode)) return true;
    if (err.statusCode === 404) return true;
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
