import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

/** Deterministic sha256 of a string, used to key cached analysis by input content. */
export function contentHash(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Content-hash cache under ~/.orgintel/cache/<orgId>/<kind>/<hash>.json. Analysis of a
 * component is keyed by a hash of that component's source, so re-runs only re-analyse
 * changed components. Determinism-preserving: the cache is a pure memo of a pure function.
 */
export class OrgIntelCache {
  private readonly dir: string;

  constructor(orgId: string, baseDir: string = join(homedir(), '.orgintel', 'cache')) {
    this.dir = join(baseDir, orgId);
  }

  private pathFor(kind: string, hash: string): string {
    return join(this.dir, kind, `${hash}.json`);
  }

  get<T>(kind: string, hash: string): T | null {
    const p = this.pathFor(kind, hash);
    if (!existsSync(p)) return null;
    try {
      return JSON.parse(readFileSync(p, 'utf8')) as T;
    } catch {
      return null;
    }
  }

  set<T>(kind: string, hash: string, value: T): void {
    const p = this.pathFor(kind, hash);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(value), 'utf8');
  }

  /** Return cached analysis for `content`, or run `analyze`, cache, and return it. */
  async memoize<T>(kind: string, content: string, analyze: () => Promise<T> | T): Promise<T> {
    const hash = contentHash(content);
    const hit = this.get<T>(kind, hash);
    if (hit !== null) return hit;
    const value = await analyze();
    this.set(kind, hash, value);
    return value;
  }
}
