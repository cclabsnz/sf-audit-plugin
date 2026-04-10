// src/history/HistoryStore.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AuditResult } from '../findings/AuditResult.js';

function parseResult(raw: string): AuditResult {
  const obj = JSON.parse(raw);
  obj.generatedAt = new Date(obj.generatedAt);
  return obj as AuditResult;
}

export class HistoryStore {
  private readonly root: string;

  constructor(root?: string) {
    this.root = root ?? HistoryStore.defaultRoot();
  }

  static defaultRoot(): string {
    return path.join(os.homedir(), '.sf', 'audit-history');
  }

  archive(result: AuditResult): void {
    try {
      const dir = path.join(this.root, result.orgId);
      fs.mkdirSync(dir, { recursive: true });
      const suffix = Math.random().toString(36).slice(2, 8);
      const filename = `sf-audit-${result.orgId}-${Date.now()}-${suffix}.json`;
      fs.writeFileSync(path.join(dir, filename), JSON.stringify(result, null, 2), 'utf-8');
    } catch (err) {
      process.stderr.write(`[sf-audit] Warning: could not archive audit result: ${String(err)}\n`);
    }
  }

  list(orgId: string, dir?: string): AuditResult[] {
    const searchDir = dir ? path.join(dir, orgId) : path.join(this.root, orgId);
    if (!fs.existsSync(searchDir)) return [];

    const files = fs.readdirSync(searchDir)
      .filter((f) => f.startsWith('sf-audit-') && f.endsWith('.json'))
      .map((f) => path.join(searchDir, f));

    const results: AuditResult[] = [];
    for (const file of files) {
      try {
        results.push(parseResult(fs.readFileSync(file, 'utf-8')));
      } catch {
        // skip unparseable files silently
      }
    }

    return results.sort((a, b) => a.generatedAt.getTime() - b.generatedAt.getTime());
  }

  latest(orgId: string, dir?: string): AuditResult | null {
    const all = this.list(orgId, dir);
    return all.length > 0 ? all[all.length - 1] : null;
  }

  load(filePath: string): AuditResult {
    return parseResult(fs.readFileSync(filePath, 'utf-8'));
  }
}
