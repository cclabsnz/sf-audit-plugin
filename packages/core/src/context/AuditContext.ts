import type { SoqlClient } from '../api/SoqlClient.js';
import type { ToolingClient } from '../api/ToolingClient.js';
import type { RestClient } from '../api/RestClient.js';
import type { MetadataClient } from '../api/MetadataClient.js';
import type { OrgInfo } from './OrgInfo.js';
import type { AuditCache } from './AuditCache.js';

// Run-time options that originate from `sf audit security` flags and reach individual
// checks through the context. Optional so unit-test and reduced call sites can omit it;
// checks must treat an absent value as the safe default (e.g. resolveDomains defaults off).
export interface AuditOptions {
  // From --resolve-domains. When true, TrustedUrlHygieneCheck performs outbound DNS
  // lookups against non-Salesforce trusted domains. Default runs stay org-only.
  resolveDomains?: boolean;
}

export interface AuditContext {
  readonly soql: SoqlClient;
  readonly tooling: ToolingClient;
  readonly rest: RestClient;
  // Optional: reads Metadata API components (SecuritySettings, …). Checks that use
  // it must handle its absence (advisory fallback), since unit-test contexts and
  // any reduced call sites may omit it.
  readonly metadata?: MetadataClient;
  readonly orgInfo: OrgInfo;
  readonly options?: AuditOptions;
  cache: AuditCache;
}
