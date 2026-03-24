import type { SoqlClient } from '../api/SoqlClient.js';
import type { ToolingClient } from '../api/ToolingClient.js';
import type { RestClient } from '../api/RestClient.js';
import type { QueryRegistry } from '../queries/QueryRegistry.js';
import type { OrgInfo } from './OrgInfo.js';
import type { AuditCache } from './AuditCache.js';

export interface AuditContext {
  readonly soql: SoqlClient;
  readonly tooling: ToolingClient;
  readonly rest: RestClient;
  readonly queries: QueryRegistry;
  readonly orgInfo: OrgInfo;
  cache: AuditCache;
}
