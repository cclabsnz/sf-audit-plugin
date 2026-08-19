import { jest } from '@jest/globals';
import { DataClassificationCheck } from '../../../../src/checks/impl/DataClassificationCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { CheckResult } from '../../../../src/checks/SecurityCheck.js';

const OBJECTS = ['Account', 'Contact', 'Lead', 'Opportunity', 'Case', 'Contract', 'User'];

function makeCtx(opts: {
  classified?: Array<{ objectName: string; classifiedCount: number }> | Error;
  keys?: unknown[] | Error;
} = {}): AuditContext {
  return {
    soql: {
      queryAll: jest.fn(),
      query: (jest.fn() as any).mockImplementation(() =>
        opts.keys instanceof Error
          ? Promise.reject(opts.keys)
          : Promise.resolve({ totalSize: 0, records: opts.keys ?? [] }),
      ),
    } as any,
    tooling: {
      query: (jest.fn() as any).mockImplementation(() =>
        opts.classified instanceof Error
          ? Promise.reject(opts.classified)
          : Promise.resolve(opts.classified ?? []),
      ),
      getRecord: jest.fn(),
    } as any,
    rest: {} as any,
    orgInfo: {
      id: 'o', name: 'n', type: 'DE', isSandbox: false,
      instance: 'NA1', instanceUrl: 'https://x.my.salesforce.com',
    },
    cache: {} as any,
  } as any;
}

const allClassified = OBJECTS.map((objectName) => ({ objectName, classifiedCount: 3 }));
const find = (r: CheckResult, id: string) => r.findings.find((f) => f.id === id);

describe('DataClassificationCheck', () => {
  const check = new DataClassificationCheck();

  it('passes when every key object has classified fields', async () => {
    const r = await check.run(makeCtx({ classified: allClassified }));
    const f = find(r, 'data-classification-ok')!;
    expect(f.passed).toBe(true);
    expect(f.detail).toContain('21 classified fields');
  });

  it.each([
    [1, 'MEDIUM'], [3, 'MEDIUM'], [4, 'HIGH'], [7, 'HIGH'],
  ])('rates %i unclassified object(s) as %s', async (missing, expected) => {
    const classified = allClassified.slice(0, OBJECTS.length - missing);
    const r = await check.run(makeCtx({ classified }));
    const f = find(r, 'data-classification-missing')!;
    expect(f.riskLevel).toBe(expected);
    expect(f.affectedItems).toHaveLength(missing);
  });

  it('treats an object with zero classified fields as unclassified', async () => {
    const classified = [{ objectName: 'Account', classifiedCount: 0 }];
    const r = await check.run(makeCtx({ classified }));
    expect(find(r, 'data-classification-missing')!.affectedItems).toHaveLength(OBJECTS.length);
  });

  it('names the objects that already have classification', async () => {
    const r = await check.run(makeCtx({ classified: [{ objectName: 'Account', classifiedCount: 5 }] }));
    expect(find(r, 'data-classification-missing')!.detail).toContain('Account (5 field(s))');
  });

  it('is inconclusive when the classification query fails', async () => {
    const r = await check.run(makeCtx({ classified: new Error('no tooling access') }));
    const f = find(r, 'data-classification-inconclusive')!;
    expect(f.inconclusive).toBe(true);
    expect(find(r, 'data-classification-ok')).toBeUndefined();
    expect(find(r, 'data-classification-missing')).toBeUndefined();
  });

  it('passes SBS-DATA-003 when Shield keys are present', async () => {
    const r = await check.run(makeCtx({
      classified: allClassified, keys: [{ Id: 'k1', DeveloperName: 'Key1' }],
    }));
    const f = find(r, 'data-encryption-shield-active')!;
    expect(f.passed).toBe(true);
    expect(f.title).toContain('1 encryption key(s)');
  });

  it('reports Shield as not detected when the query succeeds but returns nothing', async () => {
    const r = await check.run(makeCtx({ classified: allClassified, keys: [] }));
    expect(find(r, 'data-encryption-not-detected')!.riskLevel).toBe('MEDIUM');
  });

  /**
   * Unreadable is not absent. An org may hold Shield keys the audit user cannot see, so a
   * failed EncryptionKey query must not render as "Shield Platform Encryption not detected".
   */
  it('is inconclusive about Shield when EncryptionKey cannot be read', async () => {
    const r = await check.run(makeCtx({
      classified: allClassified, keys: new Error('INSUFFICIENT_ACCESS'),
    }));
    const f = find(r, 'data-encryption-inconclusive')!;
    expect(f.inconclusive).toBe(true);
    expect(find(r, 'data-encryption-not-detected')).toBeUndefined();
    expect(find(r, 'data-encryption-shield-active')).toBeUndefined();
  });

  it('evaluates classification and encryption independently', async () => {
    const r = await check.run(makeCtx({ classified: new Error('x'), keys: new Error('y') }));
    expect(find(r, 'data-classification-inconclusive')).toBeDefined();
    expect(find(r, 'data-encryption-inconclusive')).toBeDefined();
    expect(r.findings).toHaveLength(2);
  });

  it('scopes the classification query to the seven key objects', async () => {
    const ctx = makeCtx({});
    await check.run(ctx);
    const q = (ctx.tooling.query as any).mock.calls[0][0] as string;
    for (const o of OBJECTS) expect(q).toContain(`'${o}'`);
    expect(q).toMatch(/ComplianceGroup\s*!=\s*null/i);
  });
});
