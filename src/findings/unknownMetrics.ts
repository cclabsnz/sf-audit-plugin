// src/findings/unknownMetrics.ts
import type { OrgMetrics } from '@cclabsnz/sf-core';
import type { Finding } from './Finding.js';

/**
 * Metrics whose value is only meaningful when the finding that reports the same count was
 * definite. A result fills missing metrics with 0, so without this an unreadable count shows as a
 * reassuring zero on the dashboard and as an "improvement" in a history diff (INT-004).
 */
const METRIC_SOURCE: Partial<Record<keyof OrgMetrics, string>> = {
  modifyAllDataUsersCount: 'users-modify-all-data',
  viewAllDataUsersCount: 'users-view-all-data',
};

/**
 * Whether a source finding gives its metric an exact value. Not when it is missing (the check did
 * not run, or failed) or inconclusive; not when its title is a lower bound ("At least N", a capped
 * read); and not for "0 user(s)", which is how v1.17 and earlier archived an unreadable count.
 */
function exact(source: Finding | undefined): boolean {
  if (!source || source.inconclusive === true) return false;
  return !/^(At least |0 user\(s\))/.test(source.title);
}

/** Metrics that are unknown in this result, so must not be shown or compared as numbers. */
export function unknownMetrics(findings: Finding[]): Set<keyof OrgMetrics> {
  const unknown = new Set<keyof OrgMetrics>();
  for (const [key, id] of Object.entries(METRIC_SOURCE) as Array<[keyof OrgMetrics, string]>) {
    if (!exact(findings.find((f) => f.id === id))) unknown.add(key);
  }
  return unknown;
}
