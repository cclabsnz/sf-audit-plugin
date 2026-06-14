import type { SoqlClient } from '../api/SoqlClient.js';
import type { ToolingClient } from '../api/ToolingClient.js';
import type { RestClient } from '../api/RestClient.js';
import type { OrgInfo } from './OrgInfo.js';
import type { AuditCache } from './AuditCache.js';

export interface AuditContext {
  readonly soql: SoqlClient;
  readonly tooling: ToolingClient;
  readonly rest: RestClient;
  readonly orgInfo: OrgInfo;
  cache: AuditCache;
}
