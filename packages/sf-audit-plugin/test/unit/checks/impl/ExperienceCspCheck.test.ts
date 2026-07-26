import { jest } from '@jest/globals';
import { ExperienceCspCheck } from '../../../../src/checks/impl/ExperienceCspCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(opts: { networks?: unknown[]; throw?: boolean }): AuditContext {
  const queryAll = jest.fn() as any;
  queryAll.mockImplementation(async () => {
    if (opts.throw) throw new Error('no access');
    return opts.networks ?? [];
  });
  return {
    soql: { query: jest.fn(), queryAll } as any,
    tooling: { query: jest.fn(), getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: {},
  } as any;
}

describe('ExperienceCspCheck', () => {
  const check = new ExperienceCspCheck();

  it('is inconclusive when Network is inaccessible', async () => {
    const r = await check.run(makeCtx({ throw: true }));
    expect(r.findings[0].id).toBe('experience-csp-inconclusive');
  });

  it('passes when there are no live sites', async () => {
    const r = await check.run(makeCtx({ networks: [] }));
    expect(r.findings.some((f) => f.id === 'experience-csp-none' && f.passed)).toBe(true);
  });

  it('emits a manual-verify advisory for live sites', async () => {
    const r = await check.run(makeCtx({ networks: [{ Id: '0DB', Name: 'Portal', Status: 'Live' }] }));
    const f = r.findings.find((x) => x.id === 'experience-csp-verify');
    expect(f?.riskLevel).toBe('INFO');
    expect(f!.affectedItems?.[0].label).toBe('Portal');
  });
});
