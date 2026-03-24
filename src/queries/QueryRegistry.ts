import * as fs from 'node:fs';
import * as path from 'node:path';
import { QueryFileSchema, type QueryDefinition } from './QueryDefinition.js';
import type { QueryResult } from '../api/SoqlClient.js';

// Minimal context type — full AuditContext defined in Task 5
interface QueryContext {
  soql: {
    queryAll<T>(soql: string): Promise<T[]>;
    query<T>(soql: string): Promise<QueryResult<T>>;
  };
  tooling: { query<T>(soql: string): Promise<T[]> };
  rest: { get<T>(path: string): Promise<T> };
}

function warnFallback(id: string, err: unknown): void {
  const msg = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[QueryRegistry] Query '${id}' failed (fallbackOnError): ${msg}\n`);
}

export class QueryRegistry {
  private readonly map: ReadonlyMap<string, QueryDefinition>;

  private constructor(entries: Map<string, QueryDefinition>) {
    this.map = entries;
  }

  static load(configDir: string): QueryRegistry {
    const queryDir = path.join(configDir, 'config', 'queries');
    const files = ['soql.json', 'tooling.json'];
    const entries = new Map<string, QueryDefinition>();

    for (const file of files) {
      const filePath = path.join(queryDir, file);
      let raw: unknown;
      try {
        raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      } catch (err) {
        throw new Error(
          `QueryRegistry: failed to read ${filePath}: ${(err as Error).message}`
        );
      }

      const parsed = QueryFileSchema.safeParse(raw);
      if (!parsed.success) {
        throw new Error(
          `QueryRegistry: invalid schema in ${file}:\n${parsed.error.message}`
        );
      }

      for (const [key, def] of Object.entries(parsed.data)) {
        if (entries.has(key)) {
          throw new Error(
            `QueryRegistry: duplicate key '${key}' found in ${file}`
          );
        }
        entries.set(key, def);
      }
    }

    return new QueryRegistry(entries);
  }

  get(id: string): QueryDefinition {
    const def = this.map.get(id);
    if (!def) {
      throw new Error(`QueryRegistry: unknown query key '${id}'`);
    }
    return def;
  }

  async execute<T>(id: string, ctx: QueryContext): Promise<T[] | null> {
    const def = this.get(id);
    try {
      if (def.api === 'soql') {
        if (!def.soql) throw new Error(`Query '${id}' has api='soql' but no soql field`);
        return await ctx.soql.queryAll<T>(def.soql);
      }
      if (def.api === 'tooling') {
        if (!def.soql) throw new Error(`Query '${id}' has api='tooling' but no soql field`);
        return await ctx.tooling.query<T>(def.soql);
      }
      throw new Error(
        `QueryRegistry.execute: api='rest' entries cannot be executed here. ` +
        `Use ctx.rest.get() or ctx.tooling.getRecord() directly. Key: '${id}'`
      );
    } catch (err) {
      if (def.fallbackOnError) {
        warnFallback(id, err);
        return null;
      }
      throw err;
    }
  }

  async executeQuery<T>(id: string, ctx: QueryContext): Promise<QueryResult<T> | null> {
    const def = this.get(id);
    if (def.api !== 'soql') {
      throw new Error(`QueryRegistry.executeQuery: query '${id}' must have api='soql'`);
    }
    if (!def.soql) {
      throw new Error(`Query '${id}' has api='soql' but no soql field`);
    }
    try {
      return await ctx.soql.query<T>(def.soql);
    } catch (err) {
      if (def.fallbackOnError) {
        warnFallback(id, err);
        return null;
      }
      throw err;
    }
  }

  getAll(): ReadonlyMap<string, QueryDefinition> {
    return this.map;
  }
}
