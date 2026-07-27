/**
 * Small facts about how the Salesforce platform actually behaves, learned the hard way by
 * running against real orgs. They live in core so a plugin cannot rediscover them by
 * shipping the bug first.
 */

/**
 * True for a real 15- or 18-character Salesforce Id.
 *
 * Not every Id-shaped field contains one: `FlowDefinitionView.ActiveVersionId` returns a
 * durable name (`ns__Flow-1`) for managed-package flows. Feeding that to a WHERE clause
 * yields `invalid ID field`, once per row.
 */
export function isSalesforceId(value: string): boolean {
  return /^[a-zA-Z0-9]{15}$|^[a-zA-Z0-9]{18}$/.test(value);
}

/**
 * Salesforce error text flattened to a single line and trimmed to fit in a note.
 *
 * Retrieval code must never swallow these. A bare `catch {}` is how `intel map` silently
 * produced an Apex-only graph against a real org for an entire milestone — the operator
 * could not tell a permissions problem from a wrong-API bug.
 */
export function describeSalesforceError(e: unknown, maxLength = 180): string {
  const raw = e instanceof Error ? e.message : String(e);
  const oneLine = raw.replace(/\s+/g, ' ').trim();
  return oneLine.length > maxLength ? `${oneLine.slice(0, maxLength - 3)}…` : oneLine;
}

/**
 * Managed-package Apex bodies come back as the literal string `(hidden)`. Treat that as
 * absent rather than as source — a SymbolTable may still be available for the same class.
 */
export function usableApexBody(body: string | null | undefined): string | null {
  if (!body) return null;
  return body.trim() === '(hidden)' ? null : body;
}

/** `ns__Name` for namespaced components, plain `Name` otherwise. */
export function qualifiedName(name: string, namespacePrefix: string | null | undefined): string {
  return namespacePrefix ? `${namespacePrefix}__${name}` : name;
}
