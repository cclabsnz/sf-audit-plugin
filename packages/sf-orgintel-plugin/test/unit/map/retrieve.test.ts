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
        records: [{ ApiName: 'Case_Router', IsActive: true, ActiveVersionId: '301xx', LatestVersionId: '301xx' }],
      },
    ]);
    const tooling = toolingRejectingStandardObjects([
      {
        // Flow.Metadata genuinely IS a Tooling object — that part was always correct.
        test: (q) => q.includes('FROM Flow ') || q.includes('FROM Flow\n') || /FROM Flow\b/.test(q),
        records: [{ Metadata: { processType: 'AutoLaunchedFlow', status: 'Active', start: {}, recordUpdates: [] } }],
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
