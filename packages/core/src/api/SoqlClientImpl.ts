import type { Connection } from '@salesforce/core';
import type { QueryResult, SoqlClient } from './SoqlClient.js';

// AnyConn widens the return types of Connection methods to avoid
// complex jsforce generic overloads in this layer
type AnyConn = Connection & {
  query(soql: string): Promise<any>;
  autoFetchQuery(soql: string): Promise<any>;
};

export class SoqlClientImpl implements SoqlClient {
  private readonly anyConn: AnyConn;

  constructor(conn: Connection) {
    this.anyConn = conn as AnyConn;
  }

  async query<T>(soql: string): Promise<QueryResult<T>> {
    const result = await this.anyConn.query(soql);
    return {
      totalSize: result.totalSize as number,
      done: result.done as boolean,
      records: (result.records ?? []) as T[],
    };
  }

  async queryAll<T>(soql: string): Promise<T[]> {
    const result = await this.anyConn.autoFetchQuery(soql);
    return (result.records ?? []) as T[];
  }
}
