// src/incident/collect/collectBundle.ts
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import type { RestClient, SoqlClient } from '@cclabsnz/sf-core';
import { BUNDLE_PATHS, loadBundle, sha256File, writeJsonAtomic } from '../bundleIo.js';
import type { BundleManifest, LogCoverage, LogType } from '../model.js';
import { findActors } from '../analyse/actors.js';
import { loadIpRanges } from '../ipRanges.js';
import { buildWaves, parseDayWindow, readAnomalies, wavesFromWindow } from './discoverWaves.js';
import { fetchAuditTrail, loginsByDay, readLimits, snapshotGuests } from './snapshotOrg.js';
import { collectionDays, streamGuestLogs } from './streamGuestLogs.js';
import { followUpIps } from './followUp.js';

export interface CollectOptions {
  sinceDays: number;
  window?: string;
  event?: string;
  ipRangeFiles: string[];
  outputDir: string;
  warn: (m: string) => void;
}

export function defaultIncidentRoot(): string {
  return join(homedir(), '.sf', 'incidents');
}

const addDays = (d: string, n: number) => new Date(Date.parse(`${d}T00:00:00Z`) + n * 86_400_000).toISOString().slice(0, 10);

/**
 * Resume: logs a previous run into the same directory already collected, whose file still
 * matches the sha256 that run recorded. Anything else is downloaded again.
 */
async function priorLogs(dir: string, orgId: string, guestIds: Set<string>): Promise<Map<string, LogCoverage>> {
  const out = new Map<string, LogCoverage>();
  const p = join(dir, BUNDLE_PATHS.manifest);
  if (!existsSync(p)) return out;
  const prev = JSON.parse(readFileSync(p, 'utf-8')) as BundleManifest;
  const prevGuests = new Set(prev.guests.map((g) => g.id15));
  if (prev.orgId !== orgId || prevGuests.size !== guestIds.size || [...guestIds].some((g) => !prevGuests.has(g))) return out;
  for (const l of prev.logs) {
    if (l.status !== 'collected' || !l.file || !prev.files[l.file]) continue;
    const full = join(dir, l.file);
    if (existsSync(full) && (await sha256File(full)) === prev.files[l.file]) out.set(`${l.type as LogType}|${l.day}`, l);
  }
  return out;
}

export async function collectBundle(
  ctx: { soql: SoqlClient; rest: RestClient; orgId: string; orgName: string },
  opts: CollectOptions,
): Promise<{ dir: string; manifest: BundleManifest }> {
  const dir = opts.outputDir;
  mkdirSync(dir, { recursive: true });
  const collectedAt = new Date().toISOString();

  const anomalies = await readAnomalies(ctx.soql, opts.sinceDays);
  if (!anomalies.available && !opts.window) {
    throw new Error('Guest User Anomaly events are not available in this org (Threat Detection storage off or not licensed). Re-run with --window YYYY-MM-DD/YYYY-MM-DD.');
  }
  const guests = await snapshotGuests(ctx.soql, anomalies.events.map((e) => e.userId15), opts.warn);
  const waves = opts.window ? wavesFromWindow(parseDayWindow(opts.window), guests) : buildWaves(anomalies.events, guests, { event: opts.event });
  // Window mode has no wave event ids, so match on the wave's guest and UTC day instead.
  const events = anomalies.events.filter((e) => waves.some((w) => opts.window
    ? w.guestId15 === e.userId15 && w.days.includes(new Date(e.eventDate).toISOString().slice(0, 10))
    : w.eventIds.includes(e.eventIdentifier)));

  const days = collectionDays(waves);
  const guestIds = new Set(guests.map((g) => g.id15));
  const reuse = await priorLogs(dir, ctx.orgId, guestIds);
  let logs: LogCoverage[];
  try {
    logs = await streamGuestLogs(ctx, dir, days, guestIds, opts.warn, (t, d) => reuse.get(`${t}|${d}`));
  } finally {
    rmSync(join(dir, '.tmp'), { recursive: true, force: true });
  }

  const limits = await readLimits(ctx.soql);
  const auditFrom = waves.length ? addDays(waves.map((w) => w.days[0]).sort()[0], -7) : collectedAt.slice(0, 10);
  const audit = await fetchAuditTrail(ctx.soql, auditFrom, collectedAt.slice(0, 10), guests);
  const loginCounts = await loginsByDay(ctx.soql, days);

  const ipRangeFiles: string[] = [];
  for (const f of opts.ipRangeFiles) {
    const rel = `ip-ranges/${basename(f)}`;
    mkdirSync(join(dir, 'ip-ranges'), { recursive: true });
    copyFileSync(f, join(dir, rel));
    ipRangeFiles.push(rel);
  }

  writeJsonAtomic(join(dir, BUNDLE_PATHS.anomalies), events);
  writeJsonAtomic(join(dir, BUNDLE_PATHS.audit), audit.rows);
  writeJsonAtomic(join(dir, BUNDLE_PATHS.loginsByDay), loginCounts);
  writeJsonAtomic(join(dir, BUNDLE_PATHS.followUp), { logins: [], users: [] });

  const manifest: BundleManifest = {
    version: 1, complete: false, orgId: ctx.orgId, orgName: ctx.orgName, collectedAt, sinceDays: opts.sinceDays,
    detectorAvailable: anomalies.available, waves, guests, logs, audit: audit.coverage, limits, ipRangeFiles, files: {},
  };
  const seal = async (complete: boolean) => {
    manifest.complete = complete;
    const rels = [BUNDLE_PATHS.anomalies, BUNDLE_PATHS.audit, BUNDLE_PATHS.loginsByDay, BUNDLE_PATHS.followUp, ...ipRangeFiles,
      ...logs.filter((l) => l.status === 'collected' && l.file).map((l) => l.file!)];
    manifest.files = {};
    for (const rel of rels) {
      if (!existsSync(join(dir, rel))) throw new Error(`Bundle file missing at seal: ${rel}`);
      manifest.files[rel] = await sha256File(join(dir, rel));
    }
    writeJsonAtomic(join(dir, BUNDLE_PATHS.manifest), manifest);
  };
  await seal(false);

  // Second pass: actor IPs need the collected logs, and their logins need the org.
  const draft = await loadBundle(dir, { allowIncomplete: true });
  const ranges = ipRangeFiles.length ? loadIpRanges(ipRangeFiles.map((rel) => ({ name: basename(rel), text: readFileSync(join(dir, rel), 'utf-8') }))) : null;
  const ips = new Set<string>();
  for (const w of waves) for (const a of await findActors(draft, w, ranges)) a.ips.forEach((ip) => ips.add(ip));
  for (const e of events) if (e.sourceIp) ips.add(e.sourceIp);
  writeJsonAtomic(join(dir, BUNDLE_PATHS.followUp), await followUpIps(ctx.soql, [...ips]));
  await seal(true);
  return { dir, manifest };
}
