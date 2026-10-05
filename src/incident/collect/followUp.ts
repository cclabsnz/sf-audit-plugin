// src/incident/collect/followUp.ts
import type { SoqlClient } from '@cclabsnz/sf-core';
import { DEFAULTS, id15, type FollowUp } from '../model.js';
import { normaliseIp } from '../analyse/actors.js';

const CHUNK = 100;
const cleanIp = (ip: string) => (/^[0-9A-Fa-f:.]+$/.test(ip) ? ip : null);

/**
 * The forms LoginHistory.SourceIp may hold for one address. IPv4 has one; IPv6 is queried as
 * compressed, fully expanded, and zero-padded, because an exact-match IN list misses any form
 * it does not name. Matching afterwards is on normaliseIp, so all forms compare equal.
 */
export function ipForms(raw: string): string[] {
  const compressed = normaliseIp(raw);
  if (!compressed.includes(':') || compressed.includes('.')) return [compressed];
  const [head, tail] = compressed.split('::');
  const left = head ? head.split(':') : [];
  const right = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const groups = tail === undefined ? left : [...left, ...Array<string>(8 - left.length - right.length).fill('0'), ...right];
  if (groups.length !== 8) return [compressed];
  return [...new Set([compressed, groups.join(':'), groups.map((g) => g.padStart(4, '0')).join(':')])];
}

/**
 * LoginHistory for actor IPs with no date bound: the identifying login in the motivating
 * case came five days after the wave. SourceIp does not support LIKE, hence an IN list.
 */
export async function followUpIps(soql: SoqlClient, ips: string[]): Promise<FollowUp> {
  const clean = [...new Set(ips.flatMap(ipForms).map(cleanIp).filter((x): x is string => x !== null))];
  const logins: FollowUp['logins'] = [];
  let truncated = false;
  for (let i = 0; i < clean.length; i += CHUNK) {
    const list = clean.slice(i, i + CHUNK).map((ip) => `'${ip}'`).join(',');
    const rows = await soql.queryAll<{ LoginTime: string; UserId: string; SourceIp: string; Status: string; LoginUrl?: string; Browser?: string }>(
      `SELECT LoginTime, UserId, SourceIp, Status, LoginUrl, Browser FROM LoginHistory WHERE SourceIp IN (${list})`);
    if (rows.length >= DEFAULTS.auditPageCap) truncated = true;
    for (const r of rows) logins.push({ loginTime: r.LoginTime, userId15: id15(r.UserId)!, sourceIp: r.SourceIp, status: r.Status, loginUrl: r.LoginUrl, browser: r.Browser });
  }
  const userIds = [...new Set(logins.map((l) => l.userId15))];
  const users: FollowUp['users'] = [];
  for (let i = 0; i < userIds.length; i += CHUNK) {
    const list = userIds.slice(i, i + CHUNK).map((u) => `'${u.replace(/[^A-Za-z0-9]/g, '')}'`).join(',');
    const rows = await soql.queryAll<{ Id: string; Name: string; Email: string; CreatedDate: string; CreatedById: string; Profile?: { Name: string }; IsActive: boolean }>(
      `SELECT Id, Name, Email, CreatedDate, CreatedById, Profile.Name, IsActive FROM User WHERE Id IN (${list})`);
    for (const u of rows) users.push({ id15: id15(u.Id)!, name: u.Name, email: u.Email, createdDate: u.CreatedDate, createdById15: id15(u.CreatedById)!, profileName: u.Profile?.Name ?? '', isActive: u.IsActive });
  }
  logins.sort((a, c) => a.loginTime.localeCompare(c.loginTime));
  return truncated ? { logins, users, truncated } : { logins, users };
}
