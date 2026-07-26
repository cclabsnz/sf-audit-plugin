import type { IntelContext } from '../lib/wire.js';
import type { OrgBasics } from './types.js';

export function buildOrgBasics(ctx: IntelContext): OrgBasics {
  return {
    orgId: ctx.orgInfo.id,
    name: ctx.orgInfo.name,
    organizationType: ctx.orgInfo.type,
    isSandbox: ctx.orgInfo.isSandbox,
    instanceUrl: ctx.orgInfo.instanceUrl,
    apiVersion: ctx.apiVersion,
    namespace: ctx.namespace,
  };
}
