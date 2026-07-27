import { describe, it, expect } from '@jest/globals';
import { FlowRepository } from '../../../src/platform/flowRepository.js';
import { ApexRepository } from '../../../src/platform/apexRepository.js';
import { mapWithConcurrency } from '../../../src/platform/concurrency.js';
import { isSalesforceId, usableApexBody, qualifiedName } from '../../../src/platform/salesforceId.js';
import type { SoqlClient, QueryResult } from '../../../src/api/SoqlClient.js';
import type { ToolingClient } from '../../../src/api/ToolingClient.js';

/**
 * Contract tests for the platform layer.
 *
 * The mocks below refuse exactly as a real org refuses. That is the whole point: every bug
 * this layer exists to prevent was invisible to hand-written mocks that mirrored the
 * implementation instead of the platform, and so passed while production failed.
 */

const NOT_SUPPORTED = (o: string) => new Error(`sObject type '${o}' is not supported.`);
const NO_COLUMN = (c: string, o: string) => new Error(`No such column '${c}' on entity '${o}'.`);
const MULTI_ROW_METADATA = new Error(
  'When retrieving results with Metadata or FullName fields, the query qualifications must specify no more than one row for retrieval.',
);
const INVALID_ID = (v: string) => new Error(`invalid ID field: ${v}`);

/** A Tooling endpoint that refuses standard-only objects and unknown columns. */
function toolingLike(handler: (soql: string) => unknown[]): ToolingClient {
  return {
    async query<T>(soql: string): Promise<T[]> {
      if (/FROM FlowDefinitionView/.test(soql)) throw NOT_SUPPORTED('FlowDefinitionView');
      if (/FROM ApexTrigger/.test(soql) && /SymbolTable/.test(soql)) throw NO_COLUMN('SymbolTable', 'ApexTrigger');
      if (/FROM Flow\b/.test(soql) && / IN \(/.test(soql)) throw MULTI_ROW_METADATA;
      const bad = /WHERE Id = '([^']+)'/.exec(soql)?.[1];
      if (bad && !isSalesforceId(bad)) throw INVALID_ID(bad);
      return handler(soql) as T[];
    },
    async getRecord<T>(): Promise<T> {
      throw new Error('not implemented');
    },
  };
}

/** A standard SOQL endpoint that refuses Tooling-only objects. */
function soqlLike(handler: (soql: string) => unknown[]): SoqlClient {
  return {
    async query<T>(soql: string): Promise<QueryResult<T>> {
      const records = handler(soql) as T[];
      return { totalSize: records.length, done: true, records };
    },
    async queryAll<T>(soql: string): Promise<T[]> {
      if (/FROM Flow\b/.test(soql) && !/FlowDefinitionView/.test(soql)) throw NOT_SUPPORTED('Flow');
      return handler(soql) as T[];
    },
  };
}

const ID_A = '30109000000AbCdEAA';

describe('FlowRepository', () => {
  it('reads FlowDefinitionView through the standard API', async () => {
    const repo = new FlowRepository(
      soqlLike(() => [{ ApiName: 'Case_Router', IsActive: true, ActiveVersionId: ID_A, LatestVersionId: ID_A }]),
      toolingLike(() => []),
    );

    const defs = await repo.listDefinitions();

    expect(defs).toEqual([{ apiName: 'Case_Router', isActive: true, activeVersionId: ID_A, latestVersionId: ID_A }]);
  });

  it('reads flow metadata through Tooling, one row at a time', async () => {
    const seen: string[] = [];
    const repo = new FlowRepository(
      soqlLike(() => []),
      toolingLike((q) => {
        seen.push(q);
        return [{ Id: ID_A, Metadata: { processType: 'AutoLaunchedFlow' } }];
      }),
    );

    const md = await repo.fetchMetadata(ID_A);

    expect(md).toEqual({ processType: 'AutoLaunchedFlow' });
    expect(seen[0]).not.toContain(' IN (');
  });

  it('refuses to put a non-Id into a WHERE clause', async () => {
    const repo = new FlowRepository(soqlLike(() => []), toolingLike(() => []));

    await expect(repo.fetchMetadata('service_email__CaseContact-1')).rejects.toThrow(/non-Id value/);
  });

  describe('selectVersions', () => {
    const defs = [
      { apiName: 'Real', isActive: true, activeVersionId: ID_A, latestVersionId: ID_A },
      { apiName: 'Managed', isActive: true, activeVersionId: 'service_email__CaseContact-1', latestVersionId: null },
      { apiName: 'Inactive', isActive: false, activeVersionId: null, latestVersionId: '30109000000ZzZzEAA' },
    ];

    it('keeps only real Ids and counts managed-package flows', () => {
      const { versions, managedSkipped } = FlowRepository.selectVersions(defs);

      expect(versions).toEqual([{ id: ID_A, apiName: 'Real' }]);
      expect(managedSkipped).toBe(1);
    });

    it('includes inactive flows when asked', () => {
      const { versions } = FlowRepository.selectVersions(defs, { includeInactive: true });

      expect(versions.map((v) => v.apiName)).toEqual(['Real', 'Inactive']);
    });
  });
});

describe('ApexRepository', () => {
  it('requests SymbolTable for classes but never for triggers', async () => {
    const seen: string[] = [];
    const repo = new ApexRepository(
      toolingLike((q) => {
        seen.push(q);
        if (/FROM ApexClass/.test(q)) return [{ Name: 'Svc', NamespacePrefix: null, Body: 'class Svc{}', SymbolTable: { x: 1 } }];
        return [{ Name: 'AccTrigger', NamespacePrefix: 'ns', TableEnumOrId: 'Account', Body: 'trigger t on Account{}' }];
      }),
    );

    const classes = await repo.listClasses();
    const triggers = await repo.listTriggers();

    expect(classes[0].symbolTable).toEqual({ x: 1 });
    expect(triggers[0].name).toBe('ns__AccTrigger');
    expect(seen.find((q) => /ApexClass/.test(q))).toContain('SymbolTable');
    expect(seen.find((q) => /ApexTrigger/.test(q))).not.toContain('SymbolTable');
  });

  it('treats a withheld managed body as absent', async () => {
    const repo = new ApexRepository(
      toolingLike(() => [{ Name: 'Pkg', NamespacePrefix: 'ns', Body: '(hidden)', SymbolTable: null }]),
    );

    const classes = await repo.listClasses();

    expect(classes[0].body).toBeNull();
  });
});

describe('platform helpers', () => {
  it('accepts 15- and 18-character Ids and rejects durable names', () => {
    expect(isSalesforceId('30109000000AbCd')).toBe(true);
    expect(isSalesforceId(ID_A)).toBe(true);
    expect(isSalesforceId('service_email__CaseContact-1')).toBe(false);
    expect(isSalesforceId('')).toBe(false);
  });

  it('qualifies names by namespace only when present', () => {
    expect(qualifiedName('Svc', 'ns')).toBe('ns__Svc');
    expect(qualifiedName('Svc', null)).toBe('Svc');
  });

  it('treats "(hidden)" as no body', () => {
    expect(usableApexBody('(hidden)')).toBeNull();
    expect(usableApexBody('  (hidden) ')).toBeNull();
    expect(usableApexBody('class X{}')).toBe('class X{}');
    expect(usableApexBody(null)).toBeNull();
  });
});

describe('mapWithConcurrency', () => {
  it('runs several tasks at once but never more than the limit', async () => {
    let inFlight = 0;
    let peak = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);
    const done: number[] = [];

    await mapWithConcurrency(items, 4, async (i) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 2));
      inFlight--;
      done.push(i);
    });

    expect(done).toHaveLength(20);
    expect(peak).toBeGreaterThan(1);
    expect(peak).toBeLessThanOrEqual(4);
  });

  it('rejects a nonsensical limit rather than hanging', async () => {
    await expect(mapWithConcurrency([1], 0, async () => {})).rejects.toThrow(/>= 1/);
  });
});
