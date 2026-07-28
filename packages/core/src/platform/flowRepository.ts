import type { SoqlClient } from '../api/SoqlClient.js';
import type { ToolingClient } from '../api/ToolingClient.js';
import { isSalesforceId } from './salesforceId.js';

/** A row of `FlowDefinitionView` as the map pipeline needs it. */
export interface FlowDefinitionRecord {
  apiName: string;
  isActive: boolean;
  activeVersionId: string | null;
  latestVersionId: string | null;
}

/** A row of `FlowDefinitionView` as the automation index needs it. */
export interface FlowTriggerRecord {
  triggerType: string | null;
  triggerObjectOrEventLabel: string | null;
  isActive: boolean;
}

export interface FlowVersionRef {
  /** A real Salesforce Id, safe to place in a WHERE clause. */
  id: string;
  apiName: string;
}

/** An active flow version as the security checks need it (no Metadata — see class doc). */
export interface ActiveFlowVersion {
  id: string;
  masterLabel: string;
  processType: string | null;
  status: string | null;
  runInMode: string | null;
}

export interface SelectedFlowVersions {
  versions: FlowVersionRef[];
  /** Managed-package flows whose version "Id" was a durable name and so cannot be read. */
  managedSkipped: number;
}

/**
 * Read access to Flow metadata, encoding two platform facts that are easy to get wrong:
 *
 * 1. **`FlowDefinitionView` is a STANDARD object, not a Tooling one.** Querying it through
 *    the Tooling endpoint answers `sObject type 'FlowDefinitionView' is not supported.`
 * 2. **`Flow.Metadata` *is* Tooling, and is strictly one row per query.** An `Id IN (...)`
 *    batch is rejected: *"When retrieving results with Metadata or FullName fields, the
 *    query qualifications must specify no more than one row for retrieval."* Concurrency is
 *    the only lever for bulk reads — see `mapWithConcurrency`.
 *
 * Errors are never swallowed here; callers decide how to report a degraded run.
 */
export class FlowRepository {
  public constructor(
    private readonly soql: SoqlClient,
    private readonly tooling: ToolingClient,
  ) {}

  /** Flow definitions and their version Ids. Standard API. */
  public async listDefinitions(): Promise<FlowDefinitionRecord[]> {
    const rows = await this.soql.queryAll<{
      ApiName: string;
      IsActive: boolean;
      ActiveVersionId: string | null;
      LatestVersionId?: string | null;
    }>('SELECT ApiName, IsActive, ActiveVersionId, LatestVersionId FROM FlowDefinitionView');
    return rows.map((r) => ({
      apiName: r.ApiName,
      isActive: r.IsActive,
      activeVersionId: r.ActiveVersionId ?? null,
      latestVersionId: r.LatestVersionId ?? null,
    }));
  }

  /** Trigger configuration per flow, for automation counting. Standard API. */
  public async listTriggerViews(): Promise<FlowTriggerRecord[]> {
    const rows = await this.soql.queryAll<{
      TriggerType: string | null;
      TriggerObjectOrEventLabel: string | null;
      IsActive: boolean;
    }>('SELECT TriggerType, TriggerObjectOrEventLabel, IsActive FROM FlowDefinitionView');
    return rows.map((r) => ({
      triggerType: r.TriggerType ?? null,
      triggerObjectOrEventLabel: r.TriggerObjectOrEventLabel ?? null,
      isActive: r.IsActive,
    }));
  }

  /**
   * Pick the version to analyse per definition, dropping managed-package flows whose version
   * "Id" is a durable name rather than an Id. Pure — no org access.
   */
  public static selectVersions(
    definitions: readonly FlowDefinitionRecord[],
    opts: { includeInactive?: boolean } = {},
  ): SelectedFlowVersions {
    const versions: FlowVersionRef[] = [];
    let managedSkipped = 0;
    for (const d of definitions) {
      const versionId = opts.includeInactive ? d.latestVersionId ?? d.activeVersionId : d.activeVersionId;
      if (!versionId) continue;
      if (!opts.includeInactive && !d.isActive) continue;
      if (!isSalesforceId(versionId)) {
        managedSkipped++;
        continue;
      }
      versions.push({ id: versionId, apiName: d.apiName });
    }
    return { versions, managedSkipped };
  }

  /**
   * The structured metadata for one flow version (equivalent to its XML), or null if the
   * org returned no row. Tooling API, one row per call — see the class doc.
   */
  public async fetchMetadata(versionId: string): Promise<unknown | null> {
    if (!isSalesforceId(versionId)) {
      throw new Error(`Refusing to query Flow metadata for non-Id value '${versionId}'`);
    }
    const rows = await this.tooling.query<{ Id?: string; Metadata?: unknown }>(
      `SELECT Id, Metadata FROM Flow WHERE Id = '${versionId}'`,
    );
    return rows[0]?.Metadata ?? null;
  }

  /**
   * Active flow versions with their run mode. Tooling, but deliberately *without* Metadata —
   * selecting it would impose the one-row-per-query rule and make this unusable in bulk.
   */
  public async listActiveVersions(): Promise<ActiveFlowVersion[]> {
    const rows = await this.tooling.query<{
      Id: string;
      MasterLabel: string;
      ProcessType: string | null;
      Status: string | null;
      RunInMode: string | null;
    }>("SELECT Id, MasterLabel, ProcessType, Status, RunInMode FROM Flow WHERE Status = 'Active'");
    return rows.map((r) => ({
      id: r.Id,
      masterLabel: r.MasterLabel,
      processType: r.ProcessType ?? null,
      status: r.Status ?? null,
      runInMode: r.RunInMode ?? null,
    }));
  }
}
