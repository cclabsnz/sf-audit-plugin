import type { IncidentResult } from '../analyse/index.js';
import { blockOf } from '../analyse/actors.js';

const truncateIp = (ip: string): string => blockOf(ip);
// Any IPv4, including when followed by '/'; text that is already an x.y.z.0/24 block is left alone.
const IPV4 = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b(?!\.\d)(\/\d{1,2})?/g;
const IPV6 = /\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b(?:::\/64)?/gi;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;

/**
 * For sharing beyond the immediate security team: linked users become their ids, IPs become
 * /24 (or /64), and self-registrants' names (members of the public) are removed.
 */
export function redactResult(r: IncidentResult): IncidentResult {
  const c = structuredClone(r);
  for (const w of c.waves) {
    for (const a of w.actors) a.ips = [...new Set(a.ips.map(truncateIp))];
    for (const l of w.outcomes.actorLogins) l.sourceIp = truncateIp(l.sourceIp);
    for (const l of w.outcomes.identityLinks) { l.ip = truncateIp(l.ip); l.userName = l.userId15; l.email = l.userId15; }
    for (const x of w.responses.returnedContent) x.ip = truncateIp(x.ip);
    for (const s of w.outcomes.selfRegistrationsInActorWindow) s.display = 'Created new Customer User [redacted]';
  }
  const scrub = (s: string) => s
    .replace(EMAIL, '[email]')
    .replace(IPV4, (m, ip: string, mask?: string) => (ip.endsWith('.0') && mask === '/24' ? m : blockOf(ip)))
    .replace(IPV6, (m) => {
      if (m.endsWith('::/64')) return m;
      const groups = m.split(':').length;
      return groups >= 3 && (m.includes('::') || /[a-f]/i.test(m)) ? blockOf(m) : m;
    });
  return JSON.parse(JSON.stringify(c), (_k, v) => (typeof v === 'string' ? scrub(v) : v)) as IncidentResult;
}
