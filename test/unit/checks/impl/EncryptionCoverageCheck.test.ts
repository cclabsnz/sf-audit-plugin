import { jest } from '@jest/globals';
import { EncryptionCoverageCheck } from '../../../../src/checks/impl/EncryptionCoverageCheck.js';
import type { AuditContext } from '../../../../src/context/AuditContext.js';

function makeCtx(opts: { classified?: unknown[]; classifiedThrow?: boolean; describe?: Record<string, unknown>; describeThrow?: boolean }): AuditContext {
  const toolingQuery = jest.fn() as any;
  toolingQuery.mockImplementation(async () => {
    if (opts.classifiedThrow) throw new Error('no tooling');
    return opts.classified ?? [];
  });
  const get = jest.fn() as any;
  get.mockImplementation(async (path: string) => {
    if (opts.describeThrow) throw new Error('no describe');
    const obj = path.split('/')[2];
    return opts.describe?.[obj] ?? { fields: [] };
  });
  return {
    soql: { query: jest.fn(), queryAll: jest.fn() } as any,
    tooling: { query: toolingQuery, getRecord: jest.fn() } as any,
    rest: { get } as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('EncryptionCoverageCheck', () => {
  const check = new EncryptionCoverageCheck();

  it('is inconclusive when classified fields cannot be queried', async () => {
    const r = await check.run(makeCtx({ classifiedThrow: true }));
    expect(r.findings[0].id).toBe('encryption-coverage-inconclusive');
  });

  it('passes (defers) when no fields are classified', async () => {
    const r = await check.run(makeCtx({ classified: [] }));
    expect(r.findings.some((f) => f.id === 'encryption-coverage-no-classification' && f.passed)).toBe(true);
  });

  it('flags classified-but-unencrypted fields as HIGH', async () => {
    const r = await check.run(
      makeCtx({
        classified: [{ obj: 'Contact', field: 'SSN__c' }, { obj: 'Contact', field: 'Email' }],
        describe: { Contact: { fields: [{ name: 'SSN__c', encrypted: false }, { name: 'Email', encrypted: true }] } },
      }),
    );
    const f = r.findings.find((x) => x.id === 'encryption-coverage-unencrypted-sensitive');
    expect(f?.riskLevel).toBe('HIGH');
    expect(f!.affectedItems?.[0].label).toBe('Contact.SSN__c');
  });

  it('passes when all classified fields are encrypted', async () => {
    const r = await check.run(
      makeCtx({
        classified: [{ obj: 'Contact', field: 'SSN__c' }],
        describe: { Contact: { fields: [{ name: 'SSN__c', encrypted: true }] } },
      }),
    );
    expect(r.findings.some((f) => f.id === 'encryption-coverage-ok' && f.passed)).toBe(true);
  });

  it('is inconclusive when no object could be described', async () => {
    const r = await check.run(makeCtx({ classified: [{ obj: 'Contact', field: 'SSN__c' }], describeThrow: true }));
    expect(r.findings[0].id).toBe('encryption-coverage-inconclusive');
  });
});
