import type { AuditContext } from '@cclabsnz/sf-core';

/**
 * How records are shared with unauthenticated guest users, read from share tables.
 *
 * Since Winter '21 the only new way to share a record with a guest is a guest user sharing rule:
 * its rows carry RowCause 'GuestRule' and name the site's guest user group (Group Type
 * 'GuestUserGroup'), not the guest user (seen on a live org, test/fixtures/org/guest-share); the
 * parent or person-account access it implies carries 'GuestParentImplicit' / 'GuestPersonImplicit'
 * (AccountShare picklist values). Those rows are counted whoever they name. Access granted before Winter '21 was not
 * removed: manual and Apex-managed shares to a guest user, and a guest's membership of a public
 * group or queue, still give access until someone cleans them up. So rows naming a guest user
 * (other than its ownership, which is reported on its own) or a group a guest belongs to count too.
 */
export const GUEST_ROW_CAUSES = ['GuestRule', 'GuestParentImplicit', 'GuestPersonImplicit'] as const;

export interface GuestPrincipals {
  users: string[];
  /**
   * Groups whose members are guests: each site's guest user group (Group Type 'GuestUserGroup',
   * whose membership GroupMember does not list), and public groups and queues a guest user belongs
   * to. Empty when neither can be read.
   */
  groups: string[];
}

const quote = (ids: string[]) => ids.map((i) => `'${i}'`).join(', ');

export async function guestPrincipals(ctx: AuditContext, guestIds: string[]): Promise<GuestPrincipals> {
  if (guestIds.length === 0) return { users: [], groups: [] };
  const groups = new Set<string>();
  try {
    const guestGroups = await ctx.soql.queryAll<{ Id: string }>("SELECT Id FROM Group WHERE Type = 'GuestUserGroup'");
    for (const g of guestGroups ?? []) if (g?.Id) groups.add(g.Id);
  } catch {
    // Not readable: shares naming a guest user group are then found only through UserRecordAccess.
  }
  // A group that contains a group a guest belongs to gives the guest its access too, so membership
  // is followed outwards until no new group appears (bounded, in case of a cycle or a deep tree).
  let frontier = [...guestIds, ...groups];
  for (let depth = 0; depth < MAX_GROUP_DEPTH && frontier.length > 0; depth++) {
    let rows: Array<{ GroupId: string }>;
    try {
      rows = await ctx.soql.queryAll<{ GroupId: string }>(
        `SELECT GroupId FROM GroupMember WHERE UserOrGroupId IN (${quote(frontier)})`,
      );
    } catch {
      break; // Not readable: legacy group membership is then found only through UserRecordAccess.
    }
    frontier = [...new Set((rows ?? []).map((r) => r?.GroupId).filter((g): g is string => Boolean(g) && !groups.has(g)))];
    for (const g of frontier) groups.add(g);
  }
  return { users: guestIds, groups: [...groups] };
}

/** How many levels of nested public groups are followed. */
const MAX_GROUP_DEPTH = 5;

/**
 * Ground-truth read confirmation via UserRecordAccess on up to 200 sample records (the most one
 * UserRecordAccess query takes), so a share matching only some records is likelier to show.
 * UserRecordAccess takes one user per query, and each site has its own guest user with its own
 * guest sharing rules, so every guest user is asked. True when any guest reads any sampled record;
 * null when the object has no record to sample; 'failed' when either query fails.
 */
export async function guestReadsSample(ctx: AuditContext, obj: string, guestIds: string[]): Promise<boolean | null | 'failed'> {
  try {
    const sample = await ctx.soql.query<{ Id: string }>(`SELECT Id FROM ${obj} LIMIT 200`);
    const ids = (sample.records ?? []).map((r) => r.Id);
    if (ids.length === 0) return null;
    const inIds = quote(ids);
    for (const guestId of guestIds) {
      const access = await ctx.soql.queryAll<{ RecordId: string; HasReadAccess: boolean }>(
        `SELECT RecordId, HasReadAccess FROM UserRecordAccess WHERE UserId = '${guestId}' AND RecordId IN (${inIds})`,
      );
      if (access.some((a) => a.HasReadAccess === true)) return true;
    }
    return false;
  } catch {
    return 'failed';
  }
}

/** The WHERE condition matching every share row that gives a guest user access to a record. */
export function guestShareWhere(p: GuestPrincipals): string {
  const parts = [`RowCause IN (${GUEST_ROW_CAUSES.map((c) => `'${c}'`).join(', ')})`];
  if (p.users.length > 0) parts.push(`(UserOrGroupId IN (${quote(p.users)}) AND RowCause != 'Owner')`);
  if (p.groups.length > 0) parts.push(`UserOrGroupId IN (${quote(p.groups)})`);
  return parts.join(' OR ');
}

/** The share table of an object: AccountShare for standard objects, Foo__Share for Foo__c. */
export function shareTableOf(obj: string): string {
  return obj.endsWith('__c') ? `${obj.slice(0, -3)}__Share` : `${obj}Share`;
}

/** Share rows giving guests access to the object's records; null when it has no readable share table. */
export async function guestShareCount(ctx: AuditContext, obj: string, p: GuestPrincipals): Promise<number | null> {
  try {
    const r = await ctx.soql.query<unknown>(`SELECT COUNT() FROM ${shareTableOf(obj)} WHERE ${guestShareWhere(p)}`);
    return r.totalSize;
  } catch {
    return null;
  }
}
