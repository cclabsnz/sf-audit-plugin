import type { Connection } from '@salesforce/core';
import type { MetadataClient } from './MetadataClient.js';

export class MetadataClientImpl implements MetadataClient {
  constructor(private readonly conn: Connection) {}

  async read<T = Record<string, unknown>>(type: string, fullName: string): Promise<T | null> {
    // jsforce types `read` to a fixed MetadataType union; we pass through arbitrary
    // type names (e.g. 'SecuritySettings'), so call via a loosened signature.
    const read = this.conn.metadata.read.bind(this.conn.metadata) as (t: string, f: string) => Promise<unknown>;
    const res: unknown = await read(type, fullName);
    if (res == null) return null;
    const rec = Array.isArray(res) ? res[0] : res;
    // Metadata.read returns an object with only `fullName`/empty fields when the
    // component does not exist — treat that as "not present".
    if (!rec || typeof rec !== 'object') return null;
    const keys = Object.keys(rec as Record<string, unknown>).filter((k) => k !== 'fullName');
    return keys.length === 0 ? null : (rec as T);
  }
}
