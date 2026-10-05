// src/incident/collect/snapshotOrg.ts
import type { SoqlClient } from '@cclabsnz/sf-core';
import { degrades } from './orgErrors.js';
import { DEFAULTS, id15, type AuditCoverage, type AuditRow, type GuestUser, type LoginDayCount, type RunningUserLimits } from '../model.js';

const quoteIds = (ids: string[]) => ids.map((i) => `'${i.replace(/[^A-Za-z0-9]/g, '')}'`).join(',');

interface UserRow { Id: string; Username: string; Name: string; Profile?: { Name: string }; IsActive: boolean }

/** Active guests plus any user an anomaly event named, so a since-deactivated guest's rows survive filtering. */
export async function snapshotGuests(soql: SoqlClient, extraIds: string[], warn: (m: string) => void = () => {}): Promise<{ guests: GuestUser[]; warnings: string[] }> {
  const warnings: string[] = [];
  const active = await soql.queryAll<UserRow>("SELECT Id, Username, Name, Profile.Name, IsActive FROM User WHERE UserType = 'Guest' AND IsActive = true");
  const known = new Set(active.map((u) => id15(u.Id)));
  const missing = [...new Set(extraIds.map((x) => id15(x)!).filter((x) => x && !known.has(x)))];
  const extra = missing.length
    ? await soql.queryAll<UserRow>(`SELECT Id, Username, Name, Profile.Name, IsActive FROM User WHERE Id IN (${quoteIds(missing)})`)
    : [];
  const optional = async <T>(object: string, q: string): Promise<T[]> => {
    try { return await soql.queryAll<T>(q); } catch (e) {
      if (!degrades(e)) throw e;
      const m = `Could not read ${object} (${String(e)}); continuing without it.`;
      warnings.push(m);
      warn(m);
      return [];
    }
  };
  const sites = await optional<{ Name: string; GuestUserId: string | null }>('Site', 'SELECT Name, GuestUserId FROM Site');
  const users = [...active, ...extra];
  const perms = users.length
    ? await optional<{ AssigneeId: string; PermissionSet: { Label: string } }>('PermissionSetAssignment',
      `SELECT AssigneeId, PermissionSet.Label FROM PermissionSetAssignment WHERE AssigneeId IN (${quoteIds(users.map((u) => u.Id))}) AND PermissionSet.IsOwnedByProfile = false`)
    : [];
  const guests = users.map((u) => {
    const i = id15(u.Id)!;
    return {
      id15: i,
      username: u.Username,
      name: u.Name,
      profileName: u.Profile?.Name ?? '',
      permissionSetLabels: perms.filter((p) => id15(p.AssigneeId) === i).map((p) => p.PermissionSet.Label).sort(),
      siteNames: [...new Set(sites.filter((s) => id15(s.GuestUserId) === i).map((s) => s.Name))].sort(),
      active: u.IsActive && known.has(i),
    };
  });
  return { guests, warnings };
}

export async function readLimits(soql: SoqlClient): Promise<RunningUserLimits> {
  try {
    const r = await soql.queryAll<{ PermissionsQueryAllFiles: boolean; PermissionsViewAllData: boolean }>(
      'SELECT PermissionsQueryAllFiles, PermissionsViewAllData FROM UserPermissionAccess');
    return { queryAllFiles: Boolean(r[0]?.PermissionsQueryAllFiles), viewAllData: Boolean(r[0]?.PermissionsViewAllData) };
  } catch (e) {
    if (!degrades(e)) throw e;
    return { queryAllFiles: false, viewAllData: false };
  }
}

function relevant(display: string, guests: GuestUser[]): boolean {
  const t = display.toLowerCase();
  if (/^created new customer user|^reset password for user/i.test(display)) return true;
  return guests.some((g) => [g.profileName, g.name, ...g.permissionSetLabels, ...g.siteNames].some((l) => l && t.includes(l.toLowerCase())))
    || /\bsite\b|experience|network|sharing rule|guest/i.test(display);
}

/**
 * SetupAuditTrail cannot filter on Section and queryAll stops at 10,000 rows, so the range is
 * walked in 4-day windows and any window that comes back full is split in half until it fits.
 */
export async function fetchAuditTrail(soql: SoqlClient, from: string, to: string, guests: GuestUser[]): Promise<{ rows: AuditRow[]; coverage: AuditCoverage }> {
  const coverage: AuditCoverage = { from, to, truncatedWindows: [], inaccessible: false };
  const rows: AuditRow[] = [];
  const iso = (ms: number) => new Date(ms).toISOString().replace('.000Z', 'Z');
  const fetchWindow = async (startMs: number, endMs: number): Promise<void> => {
    const recs = await soql.queryAll<{ CreatedDate: string; CreatedBy?: { Name: string }; Section: string | null; Action: string; Display: string }>(
      `SELECT CreatedDate, CreatedBy.Name, Section, Action, Display FROM SetupAuditTrail WHERE CreatedDate >= ${iso(startMs)} AND CreatedDate < ${iso(endMs)}`);
    if (recs.length >= DEFAULTS.auditPageCap) {
      if (endMs - startMs <= 60_000) { coverage.truncatedWindows.push({ from: iso(startMs), to: iso(endMs) }); }
      else {
        const mid = startMs + Math.floor((endMs - startMs) / 2);
        await fetchWindow(startMs, mid);
        await fetchWindow(mid, endMs);
        return;
      }
    }
    for (const r of recs) if (relevant(r.Display ?? '', guests)) rows.push({ createdDate: r.CreatedDate, createdBy: r.CreatedBy?.Name ?? '', section: r.Section, action: r.Action, display: r.Display ?? '' });
  };
  try {
    const startMs = Date.parse(`${from}T00:00:00Z`);
    const endMs = Date.parse(`${to}T00:00:00Z`) + 86_400_000;
    for (let s = startMs; s < endMs; s += DEFAULTS.auditWindowDays * 86_400_000) await fetchWindow(s, Math.min(endMs, s + DEFAULTS.auditWindowDays * 86_400_000));
  } catch (e) {
    if (!degrades(e)) throw e;
    coverage.inaccessible = true;
  }
  rows.sort((a, c) => a.createdDate.localeCompare(c.createdDate));
  return { rows, coverage };
}

export async function loginsByDay(soql: SoqlClient, days: string[]): Promise<LoginDayCount[]> {
  if (days.length === 0) return [];
  const first = days[0];
  const last = new Date(Date.parse(`${days[days.length - 1]}T00:00:00Z`) + 86_400_000).toISOString().slice(0, 10);
  try {
    const r = await soql.queryAll<{ d: string; Status: string; n: number }>(
      `SELECT DAY_ONLY(LoginTime) d, Status, COUNT(Id) n FROM LoginHistory WHERE LoginTime >= ${first}T00:00:00Z AND LoginTime < ${last}T00:00:00Z GROUP BY DAY_ONLY(LoginTime), Status`);
    return r.filter((x) => days.includes(x.d)).map((x) => ({ day: x.d, status: x.Status, count: Number(x.n) }));
  } catch (e) {
    if (!degrades(e)) throw e;
    return [];
  }
}
