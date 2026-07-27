import type { ToolingClient } from '../api/ToolingClient.js';
import { qualifiedName, usableApexBody } from './salesforceId.js';

export interface ApexClassRecord {
  /** Namespace-qualified name (`ns__Name` where namespaced). */
  name: string;
  namespace: string | null;
  /** Source, or null when the body is withheld (managed package). */
  body: string | null;
  /** Structural symbol table when the org provides one, else null. */
  symbolTable: unknown;
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
  public async listClasses(): Promise<ApexClassRecord[]> {
    const rows = await this.tooling.query<{
      Name: string;
      NamespacePrefix: string | null;
      Body: string | null;
      SymbolTable: unknown;
    }>('SELECT Name, NamespacePrefix, Body, SymbolTable FROM ApexClass');
    return rows.map((r) => ({
      name: qualifiedName(r.Name, r.NamespacePrefix),
      namespace: r.NamespacePrefix ?? null,
      body: usableApexBody(r.Body),
      symbolTable: r.SymbolTable ?? null,
    }));
  }

  /** Apex triggers. Deliberately omits SymbolTable — the column does not exist here. */
  public async listTriggers(): Promise<ApexTriggerRecord[]> {
    const rows = await this.tooling.query<{
      Name: string;
      NamespacePrefix: string | null;
      TableEnumOrId: string;
      Body: string | null;
    }>('SELECT Name, NamespacePrefix, TableEnumOrId, Body FROM ApexTrigger');
    return rows.map((r) => ({
      name: qualifiedName(r.Name, r.NamespacePrefix),
      namespace: r.NamespacePrefix ?? null,
      tableEnumOrId: r.TableEnumOrId,
      body: usableApexBody(r.Body),
    }));
  }
}
