import type { Connection } from '@salesforce/core';
import {
  SoqlClientImpl,
  ToolingClientImpl,
  RestClientImpl,
  MetadataClientImpl,
} from '@cclabsnz/sf-core';
import type {
  SoqlClient,
  ToolingClient,
  RestClient,
  MetadataClient,
  OrgInfo,
} from '@cclabsnz/sf-core';

/**
 * The read-only client surface every OrgIntel analysis runs against. Deliberately
 * lean and dependency-free so analysis functions are pure over these interfaces and
 * testable with hand-mocked clients (no live org).
 */
export interface IntelContext {
  soql: SoqlClient;
  tooling: ToolingClient;
  rest: RestClient;
  metadata: MetadataClient;
  orgInfo: OrgInfo;
  /** API version the connection queries with (e.g. "62.0"). */
  apiVersion: string;
  /** Organization.NamespacePrefix, or null for orgs without a namespace. */
  namespace: string | null;
}

export function buildApiClients(conn: Connection): {
  soql: SoqlClient;
  tooling: ToolingClient;
  rest: RestClient;
  metadata: MetadataClient;
} {
  return {
    soql: new SoqlClientImpl(conn),
    tooling: new ToolingClientImpl(conn),
    rest: new RestClientImpl(conn),
    metadata: new MetadataClientImpl(conn),
  };
}

interface OrgRecord {
  Id: string;
  Name: string;
  OrganizationType: string;
  IsSandbox: boolean;
  InstanceName: string;
  NamespacePrefix: string | null;
}

export async function resolveOrgInfo(
  conn: Connection,
): Promise<{ orgInfo: OrgInfo; namespace: string | null }> {
  const result = await conn.query<OrgRecord>(
    'SELECT Id, Name, OrganizationType, IsSandbox, InstanceName, NamespacePrefix FROM Organization LIMIT 1',
  );
  const rec = result.records[0];
  if (!rec) throw new Error('Could not retrieve Organization record');
  return {
    orgInfo: {
      id: rec.Id,
      name: rec.Name,
      type: rec.OrganizationType,
      isSandbox: rec.IsSandbox,
      instance: rec.InstanceName,
      instanceUrl: conn.instanceUrl,
    },
    namespace: rec.NamespacePrefix ?? null,
  };
}

export function buildIntelContext(
  conn: Connection,
  orgInfo: OrgInfo,
  namespace: string | null,
  apiVersion: string,
): IntelContext {
  const clients = buildApiClients(conn);
  return {
    soql: clients.soql,
    tooling: clients.tooling,
    rest: clients.rest,
    metadata: clients.metadata,
    orgInfo,
    apiVersion,
    namespace,
  };
}
