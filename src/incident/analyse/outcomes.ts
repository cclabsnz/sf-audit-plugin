import type { Bundle } from '../bundleIo.js';
import type { AuditRow, LoginRow, Wave } from '../model.js';
import type { Actor } from './actors.js';

export interface IdentityLink { ip: string; userId15: string; userName: string; email: string; userCreatedDate: string; createdByGuest: string; loginTime: string }

export interface Outcomes {
  actorLogins: Array<LoginRow & { actorId: string }>;
  successfulLogins: number;
  failedLogins: number;
  /** Cannot be tied to an IP (the audit trail has none); listed for review, never counted as access. */
  selfRegistrationsInActorWindow: AuditRow[];
  identityLinks: IdentityLink[];
}

export function isSelfRegistration(row: AuditRow): boolean {
  return /^Created new Customer User\b/.test(row.display) || /^Reset password for user\b/.test(row.display);
}

export function computeOutcomes(b: Bundle, wave: Wave, actors: Actor[]): Outcomes {
  const actorOf = new Map(actors.flatMap((a) => a.ips.map((ip) => [ip, a.id] as const)));
  const actorLogins = b.followUp.logins.filter((l) => actorOf.has(l.sourceIp)).map((l) => ({ ...l, actorId: actorOf.get(l.sourceIp)! }));
  const ok = actorLogins.filter((l) => l.status === 'Success');
  const guestNames = new Map(b.manifest.guests.map((g) => [g.id15, g.name]));
  const waveGuestName = guestNames.get(wave.guestId15);

  const identityLinks: IdentityLink[] = [];
  for (const l of ok) {
    const u = b.followUp.users.find((x) => x.id15 === l.userId15);
    const creator = u ? guestNames.get(u.createdById15) : undefined;
    if (!u || !creator) continue;
    identityLinks.push({ ip: l.sourceIp, userId15: u.id15, userName: u.name, email: u.email, userCreatedDate: u.createdDate, createdByGuest: creator, loginTime: l.loginTime });
  }

  const windows = actors.map((a) => [a.firstSeen, a.lastSeen] as const);
  const selfRegistrationsInActorWindow = b.audit.filter((r) =>
    r.createdBy === waveGuestName && /^Created new Customer User\b/.test(r.display) &&
    windows.some(([f, t]) => {
      const at = Date.parse(r.createdDate), from = Date.parse(f), to = Date.parse(t);
      return !Number.isNaN(at) && !Number.isNaN(from) && !Number.isNaN(to) && at >= from && at <= to;
    }));

  return { actorLogins, successfulLogins: ok.length, failedLogins: actorLogins.length - ok.length, selfRegistrationsInActorWindow, identityLinks };
}
