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

// Map
export { runMap } from './map/runMap.js';
export type { MapRunResult, MapOptions } from './map/runMap.js';
export { parseFlowXml, summarizeFlow } from './map/flow/parseFlow.js';
export type { FlowSummary } from './map/flow/flowTypes.js';
export { deriveFlowEdges } from './map/flow/flowEdges.js';
export { deriveApexEdges, analyzeApex } from './map/apex/apexEdges.js';
export { assembleCouplingArtifacts } from './map/assemble.js';
export { renderMapHtml } from './report/mapReport.js';

export { TOOL_VERSION, API_VERSION } from './version.js';
