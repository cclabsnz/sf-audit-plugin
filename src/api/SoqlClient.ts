// QueryResult mirrors @salesforce/core Connection.query() return shape
export interface QueryResult<T> {
  totalSize: number;
  done: boolean;
  records: T[];
}

export interface SoqlClient {
  // Use when totalSize matters (COUNT queries, pagination metadata)
  query<T>(soql: string): Promise<QueryResult<T>>;
  // Use when you want all records — follows nextRecordsUrl automatically
  queryAll<T>(soql: string): Promise<T[]>;
}
