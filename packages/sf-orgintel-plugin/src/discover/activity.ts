import type { SoqlClient } from '@cclabsnz/sf-core';

/**
 * Activity attach rate over 90 days: Task + Event (via polymorphic What) and EmailMessage
 * (via RelatedTo) related to the object. Approximate — polymorphic filtering only counts
 * records whose What/RelatedTo type is exactly this object. Returns null if none of the
 * three activity tables are queryable for this object.
 */
export async function activityAttach(soql: SoqlClient, object: string): Promise<number | null> {
  const queries = [
    `SELECT COUNT() FROM Task WHERE WhatId != null AND What.Type = '${object}' AND CreatedDate = LAST_N_DAYS:90`,
    `SELECT COUNT() FROM Event WHERE WhatId != null AND What.Type = '${object}' AND CreatedDate = LAST_N_DAYS:90`,
    `SELECT COUNT() FROM EmailMessage WHERE RelatedToId != null AND RelatedTo.Type = '${object}' AND CreatedDate = LAST_N_DAYS:90`,
  ];

  let total = 0;
  let any = false;
  for (const q of queries) {
    try {
      const r = await soql.query<never>(q);
      total += r.totalSize;
      any = true;
    } catch {
      // object not activity-enabled or not filterable this way; skip
    }
  }
  return any ? total : null;
}
