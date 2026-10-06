/**
 * Regression variants of the synthetic scenario, one per false-assurance path found in the final
 * review. Each builds on generateScenario(), rewrites the manifest and/or logs, and re-seals the
 * changed files' sha256 so loadBundle accepts the result. Fixture values only: 10.x and RFC 5737
 * IPs, ids carrying 'xx', example.com addresses.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { csvLine, readCsvRecords } from '../../../src/incident/csv.js';
import { BUNDLE_PATHS, logPath, sha256File } from '../../../src/incident/bundleIo.js';
import type { BundleManifest, LogType } from '../../../src/incident/model.js';
import { ACTOR_IPS, BASELINE_DAYS as BASELINE_DAYS_ALL, D1 as D1_ALL, D2, GUEST_A, SITE_A, generateScenario } from './generate.js';

export type Row = Record<string, string>;

const SPILL_DAY = '2026-09-16';
const RICH_TEXT = '1$serviceComponent://ui.communities.components.aura.components.forceCommunity.richText.RichTextController/ACTION$getParsedRichTextValue=0';
const GET_ITEMS = '1$serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems=12';
export const FETCH_CASES = '1$apex://PortalService/ACTION$fetchCases=12';

export function readManifest(dir: string): BundleManifest {
  return JSON.parse(fs.readFileSync(path.join(dir, BUNDLE_PATHS.manifest), 'utf-8')) as BundleManifest;
}

export function editManifest(dir: string, fn: (m: BundleManifest) => void): void {
  const m = readManifest(dir);
  fn(m);
  fs.writeFileSync(path.join(dir, BUNDLE_PATHS.manifest), JSON.stringify(m));
}

export async function readLog(dir: string, type: LogType, day: string): Promise<{ header: string[]; rows: Row[] }> {
  const p = path.join(dir, logPath(type, day));
  const header = fs.readFileSync(p, 'utf-8').split('\n')[0].split(',').map((h) => h.replace(/^"|"$/g, ''));
  const rows: Row[] = [];
  for await (const r of readCsvRecords(p)) rows.push(r);
  return { header, rows };
}

/** Rewrites one log (fn may return a row, several rows, or null to drop it), then re-seals it. */
export async function rewriteLog(dir: string, type: LogType, day: string, fn: (row: Row) => Row | Row[] | null, append: Row[] = []): Promise<void> {
  const { header, rows } = await readLog(dir, type, day);
  const out = rows.flatMap((r) => { const x = fn({ ...r }); return x === null ? [] : Array.isArray(x) ? x : [x]; }).concat(append);
  const rel = logPath(type, day);
  fs.writeFileSync(path.join(dir, rel), csvLine(header) + out.map((r) => csvLine(header.map((h) => r[h] ?? ''))).join(''));
  const hash = await sha256File(path.join(dir, rel));
  editManifest(dir, (m) => { m.files[rel] = hash; });
}

/** Re-seals a JSON bundle file after editing it. */
export async function rewriteJson(dir: string, rel: string, value: unknown): Promise<void> {
  fs.writeFileSync(path.join(dir, rel), JSON.stringify(value));
  const hash = await sha256File(path.join(dir, rel));
  editManifest(dir, (m) => { m.files[rel] = hash; });
}

const actorRow = (r: Row) => r.USER_ID === GUEST_A && ACTOR_IPS.includes(r.CLIENT_IP);
const isGetItems = (r: Row) => r.ACTION_MESSAGE.includes('ACTION$getItems');
const isLogin = (r: Row) => r.ACTION_MESSAGE.includes('ACTION$login');

/** C1: discovery found nothing. */
export async function zeroWaves(): Promise<string> {
  const dir = await generateScenario();
  editManifest(dir, (m) => { m.waves = []; });
  return dir;
}

/** C1 / invariant: a quiet wave with no collected baseline day, so its median is null. */
export async function nullBaseline(): Promise<string> {
  const dir = await generateScenario();
  editManifest(dir, (m) => {
    m.waves = [{ id: 'W1', guestId15: GUEST_A, site: SITE_A, days: ['2026-09-14'], eventIds: [] }];
    for (const l of m.logs) if (l.type === 'AuraRequest' && l.day !== '2026-09-14') l.status = 'missing';
  });
  return dir;
}

/** C2 P4: the W3 actor rotates across 100 /24s, so no block clears the outlier threshold. */
export async function rotatingIps(): Promise<string> {
  const dir = await generateScenario();
  let k = 0;
  await rewriteLog(dir, 'AuraRequest', D2, (r) => (actorRow(r) ? { ...r, CLIENT_IP: `10.200.${k++ % 100}.1` } : r));
  return dir;
}

/** C2 P5b: 3 of the 8 actor IPs keep scanning past midnight into the baseline day after W3. */
export async function midnightSpill(): Promise<string> {
  const dir = await generateScenario();
  const aura: Row[] = [];
  const sites: Row[] = [];
  ACTOR_IPS.slice(0, 3).forEach((ip, j) => {
    for (let i = 0; i < 600; i++) {
      const ts = `${SPILL_DAY}T0${i % 2}:${String(i % 60).padStart(2, '0')}:00.000Z`;
      const rid = `RSPILL${j}${String(i).padStart(5, '0')}`;
      aura.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, USER_AGENT: '', URI: '/sfsites/aura', REQUEST_ID: rid, ACTION_MESSAGE: RICH_TEXT });
      sites.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, REQUEST_ID: rid, RESPONSE_SIZE: '1856', URI: '/sfsites/aura' });
    }
  });
  await rewriteLog(dir, 'AuraRequest', SPILL_DAY, (r) => r, aura);
  await rewriteLog(dir, 'Sites', SPILL_DAY, (r) => r, sites);
  return dir;
}

/**
 * Residual 1: the actor's spill past midnight is data reads that return 10,000 bytes. Those
 * baseline-day replies must not become the "empty" reference size for W3.
 */
export async function midnightSpillDataReads(): Promise<string> {
  const dir = await generateScenario();
  const aura: Row[] = [];
  const sites: Row[] = [];
  ACTOR_IPS.slice(0, 3).forEach((ip, j) => {
    for (let i = 0; i < 600; i++) {
      const ts = `${SPILL_DAY}T0${i % 2}:${String(i % 60).padStart(2, '0')}:00.000Z`;
      const rid = `RSPILLD${j}${String(i).padStart(5, '0')}`;
      aura.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, USER_AGENT: '', URI: '/sfsites/aura', REQUEST_ID: rid, ACTION_MESSAGE: GET_ITEMS });
      sites.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, REQUEST_ID: rid, RESPONSE_SIZE: '10000', URI: '/sfsites/aura' });
    }
  });
  await rewriteLog(dir, 'AuraRequest', SPILL_DAY, (r) => r, aura);
  await rewriteLog(dir, 'Sites', SPILL_DAY, (r) => r, sites);
  return dir;
}

/** C3: the W3 data reads go through a custom Apex method no pattern names. */
export async function customApexReplies(): Promise<string> {
  const dir = await generateScenario();
  await rewriteLog(dir, 'AuraRequest', D2, (r) => (actorRow(r) && isGetItems(r) ? { ...r, ACTION_MESSAGE: FETCH_CASES } : r));
  return dir;
}

async function setGetItemsSize(dir: string, size: number): Promise<void> {
  const ids = new Set((await readLog(dir, 'AuraRequest', D2)).rows.filter((r) => actorRow(r) && isGetItems(r)).map((r) => r.REQUEST_ID));
  await rewriteLog(dir, 'Sites', D2, (r) => (ids.has(r.REQUEST_ID) && r.RESPONSE_SIZE !== '0' ? { ...r, RESPONSE_SIZE: String(size) } : r));
}

/** C4 P8: every W3 getItems reply is 5000 bytes; the actor's logins stay at 1861. */
export async function uniformNonEmptyReplies(): Promise<string> {
  const dir = await generateScenario();
  await setGetItemsSize(dir, 5000);
  return dir;
}

/** C4 P8b: as P8, but with no logins and no baseline data access, so the empty size is inferred. */
export async function noReferenceReplies(): Promise<string> {
  const dir = await generateScenario();
  await setGetItemsSize(dir, 5000);
  await rewriteLog(dir, 'AuraRequest', D2, (r) => (actorRow(r) && isLogin(r) ? { ...r, ACTION_MESSAGE: RICH_TEXT } : r));
  return dir;
}

/** I8: the W3 day's AuraRequest log was not collected. */
export async function uncollectedWaveDay(): Promise<string> {
  const dir = await generateScenario();
  editManifest(dir, (m) => {
    const l = m.logs.find((x) => x.type === 'AuraRequest' && x.day === D2)!;
    l.status = 'missing';
    delete l.file;
  });
  return dir;
}

// ---- Patterns seen in the first real-org validation run ----------------------------------

const GET_ITEMS_MSG = '1$serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems=12';
const ALL_DAYS = [...BASELINE_DAYS_ALL, D1_ALL, D2].sort();
export const PROXY_IPS = Array.from({ length: 11 }, (_, i) => `192.0.2.${10 + i}`);

/** An always-on corporate proxy: busy every day, a little busier on the wave days. Never an actor. */
export async function alwaysOnProxy(): Promise<string> {
  const dir = await generateScenario();
  for (const day of ALL_DAYS) {
    const calls = day === D2 || day === D1_ALL ? 2070 : 1500;
    const aura: Row[] = [];
    const sites: Row[] = [];
    for (let i = 0; i < calls; i++) {
      const ip = PROXY_IPS[i % PROXY_IPS.length];
      const ts = `${day}T${String(i % 24).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:00.000Z`;
      const rid = `RPX${day.replace(/-/g, '')}${String(i).padStart(6, '0')}`;
      aura.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, USER_AGENT: `Mozilla/5.0 (Windows NT 10.0) Chrome/14${i % 9}.0`, URI: '/sfsites/aura', REQUEST_ID: rid, ACTION_MESSAGE: RICH_TEXT });
      sites.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, REQUEST_ID: rid, RESPONSE_SIZE: '1856', URI: '/sfsites/aura' });
    }
    await rewriteLog(dir, 'AuraRequest', day, (r) => r, aura);
    await rewriteLog(dir, 'Sites', day, (r) => r, sites);
  }
  return dir;
}

/** A W3 actor IP that many distinct staff users (not created through the guest site) log in from: shared egress. */
const STAFF_CREATOR = '005xx000000admn';

export async function sharedEgressActor(): Promise<string> {
  const dir = await generateScenario();
  const f = JSON.parse(fs.readFileSync(path.join(dir, BUNDLE_PATHS.followUp), 'utf-8'));
  for (let i = 0; i < 20; i++) {
    const id = `005xx00000shr${String(i).padStart(2, '0')}`;
    f.logins.push({ loginTime: `2026-09-2${i % 9}T01:00:00Z`, userId15: id, sourceIp: ACTOR_IPS[0], status: 'Success' });
    f.users.push({ id15: id, name: `Staff ${i}`, email: `staff${i}@example.com`, createdDate: '2026-08-01T00:00:00Z', createdById15: STAFF_CREATOR, profileName: 'Staff', isActive: true });
  }
  await rewriteJson(dir, BUNDLE_PATHS.followUp, f);
  return dir;
}

/** Every W3 actor getItems call shares one REQUEST_ID, which has 785 Sites rows, one of them 1 MB. */
export async function sharedRequestIds(): Promise<string> {
  const dir = await generateScenario();
  const shared = new Set<string>();
  await rewriteLog(dir, 'AuraRequest', D2, (r) => {
    if (actorRow(r) && isGetItems(r)) { shared.add(r.REQUEST_ID); return { ...r, REQUEST_ID: 'RSHARED' }; }
    return r;
  });
  const extra: Row[] = Array.from({ length: 785 }, (_, i) => ({ TIMESTAMP_DERIVED: `${D2}T04:04:${String(i % 60).padStart(2, '0')}.000Z`, USER_ID: GUEST_A, CLIENT_IP: ACTOR_IPS[0], REQUEST_ID: 'RSHARED', RESPONSE_SIZE: i === 0 ? '1023096' : '1787', URI: '/sfsites/aura' }));
  await rewriteLog(dir, 'Sites', D2, (r) => (shared.has(r.REQUEST_ID) ? null : r), extra);
  return dir;
}

/** Legitimate visitors' reads on baseline days return data: mostly 2247 bytes, sometimes an empty 1846. */
export async function realisticBaselineReads(): Promise<string> {
  const dir = await generateScenario();
  for (const day of ['2026-09-14', '2026-09-16']) {
    const aura: Row[] = [];
    const sites: Row[] = [];
    for (let i = 0; i < 600; i++) {
      const ip = `10.250.${i % 20}.1`;
      const ts = `${day}T${String(i % 24).padStart(2, '0')}:00:00.000Z`;
      const rid = `RBR${day.replace(/-/g, '')}${String(i).padStart(5, '0')}`;
      aura.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, USER_AGENT: 'Mozilla/5.0', URI: '/sfsites/aura', REQUEST_ID: rid, ACTION_MESSAGE: GET_ITEMS_MSG });
      sites.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, REQUEST_ID: rid, RESPONSE_SIZE: i % 6 === 0 ? '1846' : '2247', URI: '/sfsites/aura' });
    }
    await rewriteLog(dir, 'AuraRequest', day, (r) => r, aura);
    await rewriteLog(dir, 'Sites', day, (r) => r, sites);
  }
  return dir;
}

/** Ordinary visitors' getItems on the scan day: 100 empty lists (1846) and 50 data-bearing replies (5000). */
export async function visitorReadsOnScanDay(): Promise<string> {
  const dir = await generateScenario();
  const aura: Row[] = [];
  const sites: Row[] = [];
  for (let i = 0; i < 150; i++) {
    const ip = `10.${(i % 20) + 1}.0.1`;
    const ts = `${D2}T${String(i % 24).padStart(2, '0')}:30:00.000Z`;
    const rid = `RVR${String(i).padStart(5, '0')}`;
    aura.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, USER_AGENT: 'Mozilla/5.0', URI: '/sfsites/aura', REQUEST_ID: rid, ACTION_MESSAGE: GET_ITEMS_MSG });
    sites.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, REQUEST_ID: rid, RESPONSE_SIZE: i < 100 ? '1846' : '5000', URI: '/sfsites/aura' });
  }
  await rewriteLog(dir, 'AuraRequest', D2, (r) => r, aura);
  await rewriteLog(dir, 'Sites', D2, (r) => r, sites);
  // The same action is normal on baseline days too (other visitors, other blocks), so the
  // wave-day visitor content is context, not evidence.
  for (const day of ['2026-09-14', '2026-09-16']) {
    const a: Row[] = [];
    const st: Row[] = [];
    for (let i = 0; i < 60; i++) {
      const ip = `10.240.${i % 20}.1`;
      const ts = `${day}T${String(i % 24).padStart(2, '0')}:10:00.000Z`;
      const rid = `RVB${day.replace(/-/g, '')}${String(i).padStart(4, '0')}`;
      a.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, USER_AGENT: 'Mozilla/5.0', URI: '/sfsites/aura', REQUEST_ID: rid, ACTION_MESSAGE: GET_ITEMS_MSG });
      st.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, REQUEST_ID: rid, RESPONSE_SIZE: i % 3 === 0 ? '1846' : '5000', URI: '/sfsites/aura' });
    }
    await rewriteLog(dir, 'AuraRequest', day, (r) => r, a);
    await rewriteLog(dir, 'Sites', day, (r) => r, st);
  }
  return dir;
}
// ---- Adversarial cases from the pre-merge review -------------------------------------------

const FETCH_CASES_MSG = '1$apex://PortalService/ACTION$fetchCases=12';

async function addFollowUp(dir: string, logins: Array<{ user: string; ip: string; status: string; creator: string }>): Promise<void> {
  const f = JSON.parse(fs.readFileSync(path.join(dir, BUNDLE_PATHS.followUp), 'utf-8'));
  for (const l of logins) {
    f.logins.push({ loginTime: '2026-09-15T05:00:00Z', userId15: l.user, sourceIp: l.ip, status: l.status });
    if (!f.users.some((u: { id15: string }) => u.id15 === l.user)) {
      f.users.push({ id15: l.user, name: `User ${l.user.slice(-3)}`, email: `${l.user.slice(-3)}@example.com`, createdDate: '2026-01-01T00:00:00Z', createdById15: l.creator, profileName: 'P', isActive: true });
    }
  }
  await rewriteJson(dir, BUNDLE_PATHS.followUp, f);
}

/** Review C1a: an actor IP fails against 9 existing staff accounts, then succeeds on a 10th. */
export async function credentialStuffing(): Promise<string> {
  const dir = await generateScenario();
  const logins = Array.from({ length: 9 }, (_, i) => ({ user: `005xx000000cs${String(i).padStart(2, '0')}`, ip: ACTOR_IPS[0], status: 'Invalid Password', creator: STAFF_CREATOR }));
  logins.push({ user: '005xx000000cs99', ip: ACTOR_IPS[0], status: 'Success', creator: STAFF_CREATOR });
  await addFollowUp(dir, logins);
  return dir;
}

/** Review C1b: the actor self-registers 10 throwaway users and logs in as each. */
export async function selfRegisteredThrowaways(): Promise<string> {
  const dir = await generateScenario();
  await addFollowUp(dir, Array.from({ length: 10 }, (_, i) => ({ user: `005xx000000tw${String(i).padStart(2, '0')}`, ip: ACTOR_IPS[0], status: 'Success', creator: GUEST_A })));
  return dir;
}

/** Review C2: an actor-less attacker calls a custom read only it uses, 9000 bytes each, from 60 /24s. */
export async function actorlessCustomReads(): Promise<string> {
  const dir = await generateScenario();
  const aura: Row[] = [];
  const sites: Row[] = [];
  for (let i = 0; i < 600; i++) {
    const ip = `10.${100 + (i % 60)}.${Math.floor(i / 60)}.1`;
    const ts = `${D2}T${String(i % 24).padStart(2, '0')}:20:00.000Z`;
    const rid = `RCR${String(i).padStart(5, '0')}`;
    aura.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, USER_AGENT: 'Mozilla/5.0', URI: '/sfsites/aura', REQUEST_ID: rid, ACTION_MESSAGE: FETCH_CASES_MSG });
    sites.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, REQUEST_ID: rid, RESPONSE_SIZE: '9000', URI: '/sfsites/aura' });
  }
  // Keep the scanner's 40 failed logins (below the actor floor): they are the independent reference.
  await rewriteLog(dir, 'AuraRequest', D2, (r) => (actorRow(r) && !isLogin(r) ? null : r), aura);
  await rewriteLog(dir, 'Sites', D2, (r) => r, sites);
  return dir;
}

/** Review C3: the scanner block gets only empty replies; 5 custom reads from other IPs return 9 KB. */
export async function exfilFromOtherIps(): Promise<string> {
  const dir = await generateScenario();
  await rewriteLog(dir, 'Sites', D2, (r) => (ACTOR_IPS.includes(r.CLIENT_IP) && Number(r.RESPONSE_SIZE) > 1900 && Number(r.RESPONSE_SIZE) < 99999 ? { ...r, RESPONSE_SIZE: '1846' } : r));
  const aura: Row[] = [];
  const sites: Row[] = [];
  for (let i = 0; i < 5; i++) {
    const ip = `198.51.100.${10 + i}`;
    const ts = `${D2}T06:0${i}:00.000Z`;
    const rid = `REX${i}`;
    aura.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, USER_AGENT: 'Mozilla/5.0', URI: '/sfsites/aura', REQUEST_ID: rid, ACTION_MESSAGE: FETCH_CASES_MSG });
    sites.push({ TIMESTAMP_DERIVED: ts, USER_ID: GUEST_A, CLIENT_IP: ip, REQUEST_ID: rid, RESPONSE_SIZE: '9000', URI: '/sfsites/aura' });
  }
  await rewriteLog(dir, 'AuraRequest', D2, (r) => r, aura);
  await rewriteLog(dir, 'Sites', D2, (r) => r, sites);
  return dir;
}

/** Review C4: only one baseline day is collected, and the scan spilled 2000 calls into its first two hours. */
export async function singleBaselineSpill(): Promise<string> {
  const dir = await generateScenario();
  const aura: Row[] = [];
  ACTOR_IPS.slice(0, 4).forEach((ip, j) => {
    for (let i = 0; i < 500; i++) {
      aura.push({ TIMESTAMP_DERIVED: `2026-09-16T0${i % 2}:${String(i % 60).padStart(2, '0')}:00.000Z`, USER_ID: GUEST_A, CLIENT_IP: ip, USER_AGENT: '', URI: '/sfsites/aura', REQUEST_ID: `RSB${j}${String(i).padStart(4, '0')}`, ACTION_MESSAGE: RICH_TEXT });
    }
  });
  await rewriteLog(dir, 'AuraRequest', '2026-09-16', (r) => r, aura);
  editManifest(dir, (m) => {
    for (const l of m.logs) if (['2026-06-29', '2026-07-01', '2026-09-14'].includes(l.day)) { l.status = 'missing'; delete l.file; }
  });
  return dir;
}
