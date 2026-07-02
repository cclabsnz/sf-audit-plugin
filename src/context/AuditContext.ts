import type { SoqlClient } from '../api/SoqlClient.js';
import type { ToolingClient } from '../api/ToolingClient.js';
import type { RestClient } from '../api/RestClient.js';
import type { MetadataClient } from '../api/MetadataClient.js';
import type { OrgInfo } from './OrgInfo.js';
import type { AuditCache } from './AuditCache.js';

export interface AuditContext {
  readonly soql: SoqlClient;
  readonly tooling: ToolingClient;
  readonly rest: RestClient;
  // Optional: reads Metadata API components (SecuritySettings, …). Checks that use
  // it must handle its absence (advisory fallback), since unit-test contexts and
  // any reduced call sites may omit it.
  readonly metadata?: MetadataClient;
  readonly orgInfo: OrgInfo;
  cache: AuditCache;
}
