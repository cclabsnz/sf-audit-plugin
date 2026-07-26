import { createWriteStream } from 'node:fs';
import { mkdir, rm, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import type { Connection } from '@salesforce/core';
import type { RestClient } from './RestClient.js';

export class RestClientImpl implements RestClient {
  constructor(private readonly conn: Connection) {}

  async get<T>(path: string): Promise<T> {
    const version = this.conn.getApiVersion();
    const normalised = path.startsWith('/') ? path : `/${path}`;
    return this.conn.request<T>(`/services/data/v${version}${normalised}`);
  }

  async getRaw(path: string): Promise<string> {
    const version = this.conn.getApiVersion();
    const normalised = path.startsWith('/') ? path : `/${path}`;
    // jsforce returns the raw body string for non-JSON content types (text/csv here).
    return this.conn.request<string>(`/services/data/v${version}${normalised}`);
  }

  async getRawToFile(path: string, destPath: string): Promise<number> {
    const version = this.conn.getApiVersion();
    const normalised = path.startsWith('/') ? path : `/${path}`;
    // Stream directly from the org to disk with the session bearer token, so the body is never
    // materialised as a JS string (which would fail on logs larger than ~512 MB).
    const url = `${this.conn.instanceUrl}/services/data/v${version}${normalised}`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${this.conn.accessToken ?? ''}` },
    });
    if (!res.ok || !res.body) {
      throw new Error(`Download failed for ${normalised} (HTTP ${res.status})`);
    }
    await mkdir(dirname(destPath), { recursive: true });
    try {
      await pipeline(Readable.fromWeb(res.body as WebReadableStream<Uint8Array>), createWriteStream(destPath));
    } catch (err) {
      await rm(destPath, { force: true }); // never leave a partial file behind
      throw err;
    }
    return (await stat(destPath)).size;
  }
}
