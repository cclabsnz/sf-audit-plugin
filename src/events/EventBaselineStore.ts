// src/events/EventBaselineStore.ts
// Local, on-disk archive of free EventLogFile CSVs. Mirrors HistoryStore: writes under
// ~/.sf/event-baseline/{orgId}/, takes an optional root for testability, and is best-effort
// (warns rather than throws) so a daily cron run never dies on a filesystem hiccup.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export class EventBaselineStore {
  private readonly root: string;

  constructor(root?: string) {
    this.root = root ?? EventBaselineStore.defaultRoot();
  }

  static defaultRoot(): string {
    return path.join(os.homedir(), '.sf', 'event-baseline');
  }

  /** The per-org base directory logs for this org are stored under. */
  orgDir(orgId: string): string {
    return path.join(this.root, orgId);
  }

  /** Absolute path a given log file is (or would be) stored at. */
  pathFor(orgId: string, eventType: string, logDate: string, id: string): string {
    return path.join(this.root, orgId, eventType, `${logDate}-${id}.csv`);
  }

  /** True when this EventLogFile is already on disk — the dedup / idempotency check. */
  has(orgId: string, eventType: string, logDate: string, id: string): boolean {
    return fs.existsSync(this.pathFor(orgId, eventType, logDate, id));
  }

  /** Write a CSV body verbatim; returns the saved path. Best-effort. */
  save(orgId: string, eventType: string, logDate: string, id: string, body: string): string {
    const filePath = this.pathFor(orgId, eventType, logDate, id);
    try {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, body, 'utf-8');
    } catch (err) {
      process.stderr.write(`[sf-audit] Warning: could not save event log ${id}: ${String(err)}\n`);
    }
    return filePath;
  }

  /** Write a per-run manifest JSON under {root}/{orgId}/_manifests/; returns its path. */
  writeManifest(orgId: string, manifest: unknown): string {
    const dir = path.join(this.root, orgId, '_manifests');
    const suffix = Math.random().toString(36).slice(2, 8);
    const filePath = path.join(dir, `manifest-${Date.now()}-${suffix}.json`);
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(filePath, JSON.stringify(manifest, null, 2), 'utf-8');
    } catch (err) {
      process.stderr.write(`[sf-audit] Warning: could not write event manifest: ${String(err)}\n`);
    }
    return filePath;
  }
}
