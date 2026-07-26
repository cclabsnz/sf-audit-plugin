import type { SoqlClient } from '@cclabsnz/sf-core';
import { countRows } from '../probe/query.js';

export interface ObjectVolume {
  total: number | null;
  created90d: number | null;
}

/** Total record count + 90-day creation velocity. Nulls when the object is not countable. */
export async function objectVolume(soql: SoqlClient, object: string): Promise<ObjectVolume> {
  return {
    total: await tryCount(soql, object),
    created90d: await tryCount(soql, object, 'CreatedDate = LAST_N_DAYS:90'),
  };
}

async function tryCount(soql: SoqlClient, object: string, where?: string): Promise<number | null> {
  try {
    return await countRows(soql, object, where);
  } catch {
    return null;
  }
}
