// @cclabsnz/sf-orgintel — programmatic surface (commands are discovered by oclif from lib/commands).

export type { IntelContext } from './lib/wire.js';
export { buildIntelContext, buildApiClients, resolveOrgInfo } from './lib/wire.js';
export { OrgIntelCache, contentHash } from './lib/cache.js';

// Probe
export { runProbe } from './probe/runProbe.js';
export * from './probe/types.js';
export { renderProbeHtml } from './report/probeReport.js';
export { htmlDocument } from './report/shell.js';

// Discover
export { runDiscover } from './discover/runDiscover.js';
export type { DiscoverOptions } from './discover/runDiscover.js';
export * from './discover/types.js';
export { DEFAULT_WEIGHTS, type DiscoverWeights } from './discover/scoringConfig.js';

export { TOOL_VERSION, API_VERSION } from './version.js';
