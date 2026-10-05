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
import { ACTOR_IPS, D2, GUEST_A, SITE_A, generateScenario } from './generate.js';

export type Row = Record<string, string>;

const SPILL_DAY = '2026-09-16';
const RICH_TEXT = '1$serviceComponent://ui.communities.components.aura.components.forceCommunity.richText.RichTextController/ACTION$getParsedRichTextValue=0';
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
