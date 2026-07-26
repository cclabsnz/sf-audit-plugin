// @cclabsnz/sf-orgintel — programmatic surface (commands are discovered by oclif from lib/commands).

export type { IntelContext } from './lib/wire.js';
export { buildIntelContext, buildApiClients, resolveOrgInfo } from './lib/wire.js';
export { OrgIntelCache, contentHash } from './lib/cache.js';

// Probe
export { runProbe } from './probe/runProbe.js';
export * from './probe/types.js';
export { renderProbeHtml } from './report/probeReport.js';
export { htmlDocument } from './report/shell.js';

export { TOOL_VERSION, API_VERSION } from './version.js';
