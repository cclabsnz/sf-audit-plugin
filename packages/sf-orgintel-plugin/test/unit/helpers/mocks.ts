import type { SoqlClient, ToolingClient, RestClient, MetadataClient, QueryResult } from '@cclabsnz/sf-core';

export interface SoqlHandler {
  test: (soql: string) => boolean;
  records?: unknown[];
  totalSize?: number;
  error?: Error;
}

/** Mock SoqlClient that dispatches by matching the SOQL string. Throws on unmatched queries. */
export function mockSoql(handlers: SoqlHandler[]): SoqlClient {
  const pick = (soql: string): SoqlHandler => {
    const h = handlers.find((x) => x.test(soql));
    if (!h) throw new Error(`Unexpected SOQL: ${soql}`);
    if (h.error) throw h.error;
    return h;
  };
  return {
    async query<T>(soql: string): Promise<QueryResult<T>> {
      const h = pick(soql);
      const records = (h.records ?? []) as T[];
      return { totalSize: h.totalSize ?? records.length, done: true, records };
    },
    async queryAll<T>(soql: string): Promise<T[]> {
      const h = pick(soql);
      return (h.records ?? []) as T[];
    },
  };
}

export interface SObjectEntry {
  name: string;
  label?: string;
  custom?: boolean;
  queryable?: boolean;
}

/**
 * Mock RestClient answering the global describe (`/sobjects/`) and, optionally, per-object
 * describes (`/sobjects/<name>/describe/`) from a fixture map.
 */
export function mockRest(
  sobjects: SObjectEntry[],
  describes: Record<string, unknown> = {},
): RestClient {
  const full = sobjects.map((s) => ({
    name: s.name,
    label: s.label ?? s.name,
    custom: s.custom ?? /__c$/i.test(s.name),
    queryable: s.queryable ?? true,
  }));
  return {
    async get<T>(path: string): Promise<T> {
      if (path === '/sobjects/') return { sobjects: full } as T;
      const m = /^\/sobjects\/([^/]+)\/describe\/$/.exec(path);
      if (m) {
        const d = describes[m[1]];
        if (d) return d as T;
        throw new Error(`No describe fixture for ${m[1]}`);
      }
      throw new Error(`Unexpected REST GET: ${path}`);
    },
    async getRaw(): Promise<string> {
      throw new Error('not implemented in mock');
    },
    async getRawToFile(): Promise<number> {
      return 0;
    },
  };
}

export interface ToolingHandler {
  test: (soql: string) => boolean;
  records?: unknown[];
  error?: Error;
}

/** Mock ToolingClient that dispatches query() by matching the SOQL string. */
export function mockTooling(handlers: ToolingHandler[]): ToolingClient {
  return {
    async query<T>(soql: string): Promise<T[]> {
      const h = handlers.find((x) => x.test(soql));
      if (!h) throw new Error(`Unexpected Tooling SOQL: ${soql}`);
      if (h.error) throw h.error;
      return (h.records ?? []) as T[];
    },
    async getRecord<T>(): Promise<T> {
      throw new Error('not implemented in mock');
    },
  };
}

export const noopTooling: ToolingClient = {
  async query<T>(): Promise<T[]> {
    return [];
  },
  async getRecord<T>(): Promise<T> {
    throw new Error('not implemented in mock');
  },
};

export const noopMetadata: MetadataClient = {
  async read<T>(): Promise<T | null> {
    return null;
  },
};
