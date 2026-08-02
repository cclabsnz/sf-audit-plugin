import type { Connection } from '@salesforce/core';
import { SoqlClientImpl } from '@cclabsnz/sf-core';
import { ToolingClientImpl } from '@cclabsnz/sf-core';
import { RestClientImpl } from '@cclabsnz/sf-core';
import { MetadataClientImpl } from '@cclabsnz/sf-core';
import type { AuditContext, AuditOptions } from '@cclabsnz/sf-core';
import type { OrgInfo } from '@cclabsnz/sf-core';

export function buildApiClients(conn: Connection) {
  return {
    soql: new SoqlClientImpl(conn),
    tooling: new ToolingClientImpl(conn),
    rest: new RestClientImpl(conn),
    metadata: new MetadataClientImpl(conn),
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
    instanceUrl: conn.instanceUrl,
  };
}

export function buildAuditContext(
  conn: Connection,
  orgInfo: OrgInfo,
  options?: AuditOptions,
): AuditContext {
  const clients = buildApiClients(conn);
  return {
    soql: clients.soql,
    tooling: clients.tooling,
    rest: clients.rest,
    metadata: clients.metadata,
    orgInfo,
    options,
    cache: {},
  };
}
