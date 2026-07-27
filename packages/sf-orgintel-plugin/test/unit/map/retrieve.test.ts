import { describe, it, expect } from '@jest/globals';
import { retrieveFlows, retrieveApex } from '../../../src/map/retrieve.js';
import { resolverFromEntities } from '../../../src/discover/objectResolver.js';
import { mockSoql, mockTooling, mockRest, noopMetadata } from '../helpers/mocks.js';
import type { IntelContext } from '../../../src/lib/wire.js';
import type { SoqlClient, ToolingClient } from '@cclabsnz/sf-core';

/**
 * Regression guards for two wrong-API bugs found running against a real org, both of which
 * silently degraded `intel map` to an Apex-only graph:
 *
 *   sObject type 'FlowDefinitionView' is not supported.      (queried via Tooling; it is standard)
 *   No such column 'SymbolTable' on entity 'ApexTrigger'.    (only ApexClass has SymbolTable)
 *
 * The mocks below reject exactly as the org does, so a query sent to the wrong API or asking
 * for a non-existent column fails the test instead of being quietly caught and noted.
 */

const NOT_SUPPORTED = (obj: string) => new Error(`sObject type '${obj}' is not supported.`);
const NO_COLUMN = (col: string, obj: string) =>
  new Error(`No such column '${col}' on entity '${obj}'.`);

/** Tooling rejects standard-only objects, as the real Tooling endpoint does. */
function toolingRejectingStandardObjects(handlers: Parameters<typeof mockTooling>[0]): ToolingClient {
  return mockTooling([
    { test: (q) => q.includes('FROM FlowDefinitionView'), error: NOT_SUPPORTED('FlowDefinitionView') },
    {
      test: (q) => q.includes('FROM ApexTrigger') && q.includes('SymbolTable'),
      error: NO_COLUMN('SymbolTable', 'ApexTrigger'),
    },
    ...handlers,
  ]);
}

function ctxOf(soql: SoqlClient, tooling: ToolingClient): IntelContext {
  return {
    soql,
    tooling,
    rest: mockRest([]),
    metadata: noopMetadata,
    orgInfo: { id: '00D', name: 'Test', type: 'Enterprise', isSandbox: true, instance: 'NA1', instanceUrl: 'https://x' },
    apiVersion: '62.0',
    namespace: null,
  };
}

describe('retrieveFlows', () => {
  it('queries FlowDefinitionView through the standard API, not Tooling', async () => {
    const soql = mockSoql([
      {
        test: (q) => q.includes('FROM FlowDefinitionView'),
        records: [{ ApiName: 'Case_Router', IsActive: true, ActiveVersionId: '30109000000AbCdEAA', LatestVersionId: '30109000000AbCdEAA' }],
      },
    ]);
    const tooling = toolingRejectingStandardObjects([
      {
        // Flow.Metadata genuinely IS a Tooling object — that part was always correct.
        test: (q) => q.includes('FROM Flow ') || q.includes('FROM Flow\n') || /FROM Flow\b/.test(q),
        records: [{ Id: '30109000000AbCdEAA', Metadata: { processType: 'AutoLaunchedFlow', status: 'Active', start: {}, recordUpdates: [] } }],
      },
    ]);
    const notes: string[] = [];

    const flows = await retrieveFlows(ctxOf(soql, tooling), {}, notes);

    expect(notes.filter((n) => n.includes('FlowDefinitionView'))).toEqual([]);
    expect(flows).toHaveLength(1);
    expect(flows[0].apiName).toBe('Case_Router');
  });

  it('reports why it degraded when the flow query genuinely fails', async () => {
    const soql = mockSoql([
      { test: (q) => q.includes('FROM FlowDefinitionView'), error: new Error('INSUFFICIENT_ACCESS') },
    ]);
    const notes: string[] = [];

    const flows = await retrieveFlows(ctxOf(soql, toolingRejectingStandardObjects([])), {}, notes);

    expect(flows).toEqual([]);
    // A degraded run must say *why* — "not queryable" alone cannot distinguish a
    // permissions problem from a wrong-API bug, which is what hid this for a whole milestone.
    expect(notes.some((n) => n.includes('INSUFFICIENT_ACCESS'))).toBe(true);
  });
});

describe('retrieveApex', () => {
  const resolver = resolverFromEntities([
    { QualifiedApiName: 'Account', DurableId: 'Account', KeyPrefix: '001' },
  ]);

  it('does not ask ApexTrigger for a SymbolTable column it does not have', async () => {
    const seen: string[] = [];
    const tooling: ToolingClient = {
      async query<T>(q: string): Promise<T[]> {
        seen.push(q);
        if (q.includes('FROM ApexTrigger') && q.includes('SymbolTable')) throw NO_COLUMN('SymbolTable', 'ApexTrigger');
        if (q.includes('FROM ApexTrigger')) {
          return [{ Name: 'AccountTrigger', NamespacePrefix: null, TableEnumOrId: 'Account', Body: 'trigger x on Account {}' }] as T[];
        }
        if (q.includes('FROM ApexClass')) {
          return [{ Name: 'Svc', NamespacePrefix: null, Body: 'class Svc {}', SymbolTable: null }] as T[];
        }
        throw new Error(`Unexpected Tooling SOQL: ${q}`);
      },
      async getRecord<T>(): Promise<T> {
        throw new Error('not implemented');
      },
    };
    const notes: string[] = [];

    const { classes, triggers } = await retrieveApex(ctxOf(mockSoql([]), tooling), resolver, notes);

    expect(notes.filter((n) => n.includes('ApexTrigger'))).toEqual([]);
    expect(triggers).toHaveLength(1);
    expect(triggers[0].object).toBe('Account');
    // ApexClass keeps SymbolTable — only the trigger query must drop it.
    expect(classes).toHaveLength(1);
    expect(seen.some((q) => q.includes('FROM ApexClass') && q.includes('SymbolTable'))).toBe(true);
  });
});

describe('retrieveFlows — managed packages and batching', () => {
  const defs = (rows: Array<[string, string]>) =>
    mockSoql([
      {
        test: (q) => q.includes('FROM FlowDefinitionView'),
        records: rows.map(([apiName, versionId]) => ({
          ApiName: apiName,
          IsActive: true,
          ActiveVersionId: versionId,
          LatestVersionId: versionId,
        })),
      },
    ]);

  const META = { processType: 'AutoLaunchedFlow', status: 'Active', start: {}, recordUpdates: [] };

  it('skips managed-package flows whose ActiveVersionId is not a real Id', async () => {
    // FlowDefinitionView returns a durable string (`ns__Name-1`) for managed flows, not an Id.
    // Querying it produced "invalid ID field" once per flow — 28 of them against a real org.
    const soql = defs([
      ['Case_Router', '30109000000AbCdEAA'],
      ['CaseContact', 'service_email__CaseContact-1'],
      ['DraftServiceEmail', 'service_email__DraftServiceEmail-1'],
    ]);
    const queries: string[] = [];
    const tooling: ToolingClient = {
      async query<T>(q: string): Promise<T[]> {
        queries.push(q);
        if (/FROM FlowDefinitionView/.test(q)) throw NOT_SUPPORTED('FlowDefinitionView');
        return [{ Id: '30109000000AbCdEAA', Metadata: META }] as T[];
      },
      async getRecord<T>(): Promise<T> { throw new Error('ni'); },
    };
    const notes: string[] = [];

    const flows = await retrieveFlows(ctxOf(soql, tooling), {}, notes);

    expect(flows.map((f) => f.apiName)).toEqual(['Case_Router']);
    // No malformed id may ever reach a SOQL WHERE clause.
    expect(queries.some((q) => q.includes('service_email__'))).toBe(false);
    // One aggregated note, not one per flow.
    const skipped = notes.filter((n) => /managed/i.test(n));
    expect(skipped).toHaveLength(1);
    expect(skipped[0]).toContain('2');
  });

  it('fetches flow metadata concurrently, one row per query', async () => {
    // The Tooling API refuses multi-row retrieval of Metadata/FullName:
    //   "the query qualifications must specify no more than one row for retrieval"
    // so an IN(...) batch is impossible. Concurrency is the only lever — without it a real
    // org with ~300 flows took 7 minutes.
    const rows: Array<[string, string]> = Array.from({ length: 12 }, (_, i) => [
      `Flow_${i}`,
      `30109000000Ab${String(i).padStart(2, '0')}EAA`,
    ]);
    const metaQueries: string[] = [];
    let inFlight = 0;
    let peak = 0;
    const tooling: ToolingClient = {
      async query<T>(q: string): Promise<T[]> {
        if (/FROM FlowDefinitionView/.test(q)) throw NOT_SUPPORTED('FlowDefinitionView');
        metaQueries.push(q);
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        inFlight--;
        const id = /'([^']+)'/.exec(q)![1];
        return [{ Id: id, Metadata: META }] as T[];
      },
      async getRecord<T>(): Promise<T> { throw new Error('ni'); },
    };
    const notes: string[] = [];

    const flows = await retrieveFlows(ctxOf(defs(rows), tooling), {}, notes);

    expect(flows).toHaveLength(12);
    // One row per query — never an IN clause, which the platform rejects outright.
    expect(metaQueries.every((q) => !q.includes(' IN ('))).toBe(true);
    expect(metaQueries).toHaveLength(12);
    // But not serial: several requests must be in flight at once.
    expect(peak).toBeGreaterThan(1);
  });
});
