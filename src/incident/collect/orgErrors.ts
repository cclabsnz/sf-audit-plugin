// src/incident/collect/orgErrors.ts
export type OrgErrorKind = 'unavailable' | 'no-permission' | 'error';

/** Only 'unavailable' and 'no-permission' may degrade collection; everything else must abort it. */
export function classifyOrgError(e: unknown): OrgErrorKind {
  const m = e instanceof Error ? e.message : String(e);
  if (/INVALID_TYPE|is not supported|not supported/i.test(m)) return 'unavailable';
  if (/INSUFFICIENT_ACCESS|HTTP 403/i.test(m)) return 'no-permission';
  return 'error';
}

export const degrades = (e: unknown): boolean => classifyOrgError(e) !== 'error';
