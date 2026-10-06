import { createHash } from 'node:crypto';
import { createReadStream, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { readCsvRecords } from './csv.js';
import type { AnomalyEvent, AuditRow, BundleManifest, FollowUp, LoginDayCount, LogType } from './model.js';

export const BUNDLE_PATHS = {
  manifest: 'manifest.json',
  anomalies: 'anomalies.json',
  audit: 'org/audit.json',
  loginsByDay: 'org/logins-by-day.json',
  followUp: 'org/followup.json',
} as const;

export function logPath(type: LogType, day: string): string {
  return `logs/${type}/${day}.csv`;
}

export async function sha256File(path: string): Promise<string> {
  const h = createHash('sha256');
  for await (const chunk of createReadStream(path)) h.update(chunk as Buffer);
  return h.digest('hex');
}

export function writeJsonAtomic(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const part = `${path}.part`;
  writeFileSync(part, JSON.stringify(value, null, 2));
  renameSync(part, path);
}

export class BundleIntegrityError extends Error {
  public constructor(public readonly files: string[]) {
    super(`Bundle files missing or changed since collection: ${files.join(', ')}`);
    this.name = 'BundleIntegrityError';
  }
}

export class BundleIncompleteError extends Error {
  public constructor() {
    super('Bundle collection did not finish (follow-up or sealing failed). Re-run incident collect into the same directory to resume.');
    this.name = 'BundleIncompleteError';
  }
}

export interface Bundle {
  dir: string;
  manifest: BundleManifest;
  manifestSha256: string;
  anomalies: AnomalyEvent[];
  audit: AuditRow[];
  loginsByDay: LoginDayCount[];
  followUp: FollowUp;
  rows(type: LogType, day: string): AsyncIterable<Record<string, string>>;
  hasLog(type: LogType, day: string): boolean;
}

/** Loads a bundle after checking every file against the manifest's sha256. */
export async function loadBundle(dir: string, opts: { allowIncomplete?: boolean } = {}): Promise<Bundle> {
  const manifestPath = join(dir, BUNDLE_PATHS.manifest);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as BundleManifest;
  const bad: string[] = [];
  for (const [rel, expected] of Object.entries(manifest.files)) {
    const p = join(dir, rel);
    if (!existsSync(p) || (await sha256File(p)) !== expected) bad.push(rel);
  }
  if (bad.length > 0) throw new BundleIntegrityError(bad);
  if (manifest.complete !== true && !opts.allowIncomplete) throw new BundleIncompleteError();

  const json = <T>(rel: string): T => JSON.parse(readFileSync(join(dir, rel), 'utf-8')) as T;
  const collected = new Map(manifest.logs.filter((l) => l.status === 'collected' && l.file).map((l) => [`${l.type}|${l.day}`, l.file!]));
  return {
    dir,
    manifest,
    manifestSha256: await sha256File(manifestPath),
    anomalies: json<AnomalyEvent[]>(BUNDLE_PATHS.anomalies),
    audit: json<AuditRow[]>(BUNDLE_PATHS.audit),
    loginsByDay: json<LoginDayCount[]>(BUNDLE_PATHS.loginsByDay),
    followUp: json<FollowUp>(BUNDLE_PATHS.followUp),
    hasLog: (type, day) => collected.has(`${type}|${day}`),
    rows: (type, day) => {
      const rel = collected.get(`${type}|${day}`);
      if (!rel) return (async function* () {})();
      return readCsvRecords(join(dir, rel));
    },
  };
}
