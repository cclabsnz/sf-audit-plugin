export interface ToolingClient {
  // Paginated Tooling SOQL query — returns all records across pages
  query<T>(soql: string): Promise<T[]>;
  // Per-record fetch: /tooling/sobjects/{type}/{id}/
  // Used by IpRestrictionsCheck to get ConnectedApplication Metadata blob
  getRecord<T>(type: string, id: string): Promise<T>;
}
