import type { ToolingClient } from '@cclabsnz/sf-core';

/**
 * Resolves an ApexTrigger/WorkflowRule/ProcessDefinition `TableEnumOrId` to an object API
 * name. Salesforce returns the API name for standard objects but the object *Id* for custom
 * objects, so we resolve via EntityDefinition (by DurableId and by 3-char key prefix).
 */
export interface ObjectResolver {
  resolve(tableEnumOrId: string): string | null;
}

const ID_PATTERN = /^[a-zA-Z0-9]{15}$|^[a-zA-Z0-9]{18}$/;

interface EntityRow {
  QualifiedApiName: string;
  DurableId: string;
  KeyPrefix: string | null;
}

export async function buildObjectResolver(tooling: ToolingClient): Promise<ObjectResolver> {
  try {
    const rows = await tooling.query<EntityRow>(
      'SELECT QualifiedApiName, DurableId, KeyPrefix FROM EntityDefinition',
    );
    return resolverFromEntities(rows);
  } catch {
    // Fallback: treat non-Id values as already-API-names (standard objects); custom Ids unresolved.
    return {
      resolve(t) {
        if (!t) return null;
        return ID_PATTERN.test(t) ? null : t;
      },
    };
  }
}

/** Pure constructor — used directly in tests with a fixture entity list. */
export function resolverFromEntities(rows: EntityRow[]): ObjectResolver {
  const apiNames = new Set<string>();
  const byDurable = new Map<string, string>();
  const byPrefix = new Map<string, string>();
  for (const r of rows) {
    apiNames.add(r.QualifiedApiName);
    byDurable.set(r.DurableId, r.QualifiedApiName);
    if (r.KeyPrefix) byPrefix.set(r.KeyPrefix, r.QualifiedApiName);
  }
  return {
    resolve(t) {
      if (!t) return null;
      if (apiNames.has(t)) return t;
      if (byDurable.has(t)) return byDurable.get(t)!;
      if (ID_PATTERN.test(t)) {
        const prefix = t.slice(0, 3);
        if (byPrefix.has(prefix)) return byPrefix.get(prefix)!;
      }
      return null;
    },
  };
}
