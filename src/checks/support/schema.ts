import type { AuditContext } from '@cclabsnz/sf-core';
import { isApiError } from '@cclabsnz/sf-core';

/**
 * Which fields an object has in this org, by describe (a GET, so read-only).
 *
 * Use it before querying a field that only some editions, licences or releases carry, such as a
 * permission like PermissionsManageEventLogFiles. Querying an absent field fails the whole query;
 * describing first lets a check say "not available in this org" instead of failing, and never
 * lets the absence read as a pass.
 */
export type Api = 'soql' | 'tooling';

const cache = new WeakMap<AuditContext, Map<string, Promise<ReadonlySet<string> | null>>>();

function isNotFound(err: unknown): boolean {
  if (isApiError(err) && (err.statusCode === 404 || /NOT_FOUND|INVALID_TYPE|^ERROR_HTTP_404$/i.test(err.errorCode))) return true;
  const msg = err instanceof Error ? err.message : String(err);
  return /NOT_FOUND|requested resource does not exist|is not supported/i.test(msg);
}

/** The object's field names, or null when this API does not serve the object in this org. */
export function fieldsOf(ctx: AuditContext, object: string, api: Api = 'soql'): Promise<ReadonlySet<string> | null> {
  let perCtx = cache.get(ctx);
  if (!perCtx) {
    perCtx = new Map();
    cache.set(ctx, perCtx);
  }
  const key = `${api}:${object}`;
  let pending = perCtx.get(key);
  if (!pending) {
    const path = api === 'tooling' ? `/tooling/sobjects/${object}/describe` : `/sobjects/${object}/describe`;
    pending = ctx.rest
      .get<{ fields?: Array<{ name: string }> }>(path)
      .then((d) => new Set((d.fields ?? []).map((f) => f.name)) as ReadonlySet<string>)
      .catch((err: unknown) => {
        if (isNotFound(err)) return null;
        throw err;
      });
    perCtx.set(key, pending);
  }
  return pending;
}

/** The subset of `wanted` the object has, in the order given. Empty when the object is absent. */
export async function presentFields(ctx: AuditContext, object: string, wanted: readonly string[], api: Api = 'soql'): Promise<string[]> {
  const fields = await fieldsOf(ctx, object, api);
  return fields ? wanted.filter((f) => fields.has(f)) : [];
}

/** True when the object has the field. */
export async function hasField(ctx: AuditContext, object: string, field: string, api: Api = 'soql'): Promise<boolean> {
  return (await fieldsOf(ctx, object, api))?.has(field) ?? false;
}
