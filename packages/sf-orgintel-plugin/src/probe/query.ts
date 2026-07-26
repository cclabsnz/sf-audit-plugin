import type { SoqlClient } from '@cclabsnz/sf-core';

export type QueryFailure = 'no-access' | 'not-present' | 'unknown';

/**
 * Classify a SOQL failure into a coverage reason. Deterministic string matching over the
 * Salesforce error text — good enough to distinguish "object/field absent" from "not
 * permitted" from everything else, so the probe degrades with a clear note.
 */
export function classifyQueryError(err: unknown): QueryFailure {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  if (
    msg.includes("is not supported") ||
    msg.includes('invalid_type') ||
    msg.includes('does not exist') ||
    msg.includes("doesn't exist") ||
    msg.includes('invalid object') ||
    msg.includes('sobject type') && msg.includes('not supported')
  ) {
    return 'not-present';
  }
  if (
    msg.includes('insufficient_access') ||
    msg.includes('insufficient access') ||
    msg.includes('not readable') ||
    msg.includes('no read permission') ||
    msg.includes('cannot access')
  ) {
    return 'no-access';
  }
  return 'unknown';
}

/** COUNT() over a table with an optional WHERE clause. Returns totalSize. May throw. */
export async function countRows(soql: SoqlClient, table: string, where?: string): Promise<number> {
  const clause = where ? ` WHERE ${where}` : '';
  const result = await soql.query<never>(`SELECT COUNT() FROM ${table}${clause}`);
  return result.totalSize;
}
