import type { Connection } from '@salesforce/core';
import type { RestClient } from './RestClient.js';

export class RestClientImpl implements RestClient {
  constructor(private readonly conn: Connection) {}

  async get<T>(path: string): Promise<T> {
    const version = this.conn.getApiVersion();
    const normalised = path.startsWith('/') ? path : `/${path}`;
    return this.conn.request<T>(`/services/data/v${version}${normalised}`);
  }
}
