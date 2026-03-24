import type { Connection } from '@salesforce/core';
import { SoqlClientImpl } from '../../api/SoqlClientImpl.js';
import { ToolingClientImpl } from '../../api/ToolingClientImpl.js';
import { RestClientImpl } from '../../api/RestClientImpl.js';
import type { AuditContext } from '../../context/AuditContext.js';
import type { OrgInfo } from '../../context/OrgInfo.js';
import type { QueryRegistry } from '../../queries/QueryRegistry.js';

export function buildApiClients(conn: Connection) {
  return {
    soql: new SoqlClientImpl(conn),
    tooling: new ToolingClientImpl(conn),
    rest: new RestClientImpl(conn),
  };
}

export async function resolveOrgInfo(conn: Connection): Promise<OrgInfo> {
  type OrgRecord = { Id: string; Name: string; OrganizationType: string; IsSandbox: boolean; InstanceName: string };
  const result = await conn.query<OrgRecord>(
    'SELECT Id, Name, OrganizationType, IsSandbox, InstanceName FROM Organization LIMIT 1'
  );
  const rec = result.records[0];
  if (!rec) throw new Error('Could not retrieve Organization record');
  return {
    id: rec.Id,
    name: rec.Name,
    type: rec.OrganizationType,
    isSandbox: rec.IsSandbox,
    instance: rec.InstanceName,
  };
}

export function buildAuditContext(
  conn: Connection,
  queries: QueryRegistry,
  orgInfo: OrgInfo,
): AuditContext {
  const clients = buildApiClients(conn);
  return {
    soql: clients.soql,
    tooling: clients.tooling,
    rest: clients.rest,
    queries,
    orgInfo,
    cache: {},
  };
}
