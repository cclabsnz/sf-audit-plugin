import type { ToolingClient } from '../api/ToolingClient.js';
import { isSalesforceId, qualifiedName, usableApexBody } from './salesforceId.js';

export interface ApexClassRecord {
  /** Namespace-qualified name (`ns__Name` where namespaced). */
  name: string;
  namespace: string | null;
  /** Source, or null when the body is withheld (managed package). */
  body: string | null;
  /** Structural symbol table when the org provides one, else null. */
  symbolTable: unknown;
}

/** Managed code is excluded with `NamespacePrefix = null` — org-authored classes only. */
export interface ApexScopeOptions {
  excludeManaged?: boolean;
}

export interface ApexTriggerRecord {
  name: string;
  namespace: string | null;
  /** Object API name or key-prefix/durable id — resolve via an ObjectResolver. */
  tableEnumOrId: string;
  body: string | null;
}

/**
 * Read access to Apex, encoding the field asymmetry that broke `intel map` against a real
 * org: **`ApexClass` has a `SymbolTable` column and `ApexTrigger` does not.** Selecting it
 * from `ApexTrigger` fails the whole query with
 * `No such column 'SymbolTable' on entity 'ApexTrigger'`, so trigger analysis must fall back
 * to the body.
 *
 * Errors are never swallowed here; callers decide how to report a degraded run.
 */
export class ApexRepository {
  public constructor(private readonly tooling: ToolingClient) {}

  /** Apex classes, including the SymbolTable this entity does provide. */
  public async listClasses(opts: ApexScopeOptions = {}): Promise<ApexClassRecord[]> {
    const rows = await this.tooling.query<{
      Name: string;
      NamespacePrefix: string | null;
      Body: string | null;
      SymbolTable: unknown;
    }>(`SELECT Name, NamespacePrefix, Body, SymbolTable FROM ApexClass${scope(opts)}`);
    return rows.map((r) => ({
      name: qualifiedName(r.Name, r.NamespacePrefix),
      namespace: r.NamespacePrefix ?? null,
      body: usableApexBody(r.Body),
      symbolTable: r.SymbolTable ?? null,
    }));
  }

  /** Apex triggers. Deliberately omits SymbolTable — the column does not exist here. */
  public async listTriggers(opts: ApexScopeOptions = {}): Promise<ApexTriggerRecord[]> {
    const rows = await this.tooling.query<{
      Name: string;
      NamespacePrefix: string | null;
      TableEnumOrId: string;
      Body: string | null;
    }>(`SELECT Name, NamespacePrefix, TableEnumOrId, Body FROM ApexTrigger${scope(opts)}`);
    return rows.map((r) => ({
      name: qualifiedName(r.Name, r.NamespacePrefix),
      namespace: r.NamespacePrefix ?? null,
      tableEnumOrId: r.TableEnumOrId,
      body: usableApexBody(r.Body),
    }));
  }

  /** Class count, without transferring bodies. */
  public async countClasses(opts: ApexScopeOptions = {}): Promise<number> {
    return this.count('ApexClass', opts);
  }

  /** Trigger count, without transferring bodies. */
  public async countTriggers(opts: ApexScopeOptions = {}): Promise<number> {
    return this.count('ApexTrigger', opts);
  }

  /**
   * Map class id -> name for the given ids. Ids are validated and de-duplicated first: a
   * malformed value reaching a WHERE clause fails the entire query with `invalid ID field`,
   * losing every good row alongside the bad one.
   */
  public async namesByIds(ids: readonly string[]): Promise<Map<string, string>> {
    const valid = [...new Set(ids.filter(isSalesforceId))];
    if (valid.length === 0) return new Map();
    const list = valid.map((id) => `'${id}'`).join(', ');
    const rows = await this.tooling.query<{ Id: string; Name: string }>(
      `SELECT Id, Name FROM ApexClass WHERE Id IN (${list})`,
    );
    return new Map(rows.map((r) => [r.Id, r.Name]));
  }

  private async count(entity: 'ApexClass' | 'ApexTrigger', opts: ApexScopeOptions): Promise<number> {
    // An aggregate needs an explicit alias, because a bare COUNT() reports through
    // `totalSize`, which the ToolingClient return type does not carry. The alias must not be
    // `expr0` — that is Salesforce's own auto-generated name and the API rejects it with
    // "alias is reserved: expr0".
    const rows = await this.tooling.query<{ cnt?: number }>(
      `SELECT COUNT(Id) cnt FROM ${entity}${scope(opts)}`,
    );
    return rows[0]?.cnt ?? 0;
  }
}

function scope(opts: ApexScopeOptions): string {
  return opts.excludeManaged ? ' WHERE NamespacePrefix = null' : '';
}
