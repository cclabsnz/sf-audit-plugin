import type { Connection } from '@salesforce/core';
import type { ToolingClient } from './ToolingClient.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyTooling = { query(soql: string): Promise<any> };

export class ToolingClientImpl implements ToolingClient {
  private readonly tooling: AnyTooling;

  constructor(private readonly conn: Connection) {
    this.tooling = conn.tooling as unknown as AnyTooling;
  }

  async query<T>(soql: string): Promise<T[]> {
    const result = await this.tooling.query(soql);
    let records: T[] = (result.records ?? []) as T[];
    let nextUrl: string | undefined = result.nextRecordsUrl as string | undefined;

    // Using conn.request() directly avoids the complex Query<> overload typings
    // on tooling.queryMore — the nextRecordsUrl is a plain string handled cleanly here
    while (nextUrl) {
      const next = await this.conn.request<{ records: T[]; nextRecordsUrl?: string; done: boolean }>(nextUrl);
      records = records.concat(next.records ?? []);
      nextUrl = next.nextRecordsUrl;
    }

    return records;
  }

  async getRecord<T>(type: string, id: string): Promise<T> {
    const version = this.conn.getApiVersion();
    return this.conn.request<T>(
      `/services/data/v${version}/tooling/sobjects/${type}/${id}/`
    );
  }
}
