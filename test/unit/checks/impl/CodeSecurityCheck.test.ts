import { jest } from '@jest/globals';
import { CodeSecurityCheck } from '../../../../src/checks/impl/CodeSecurityCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

function makeCtx(coverage: number | null): AuditContext {
  const query = (jest.fn() as any).mockImplementation((soql: string) => {
    if (soql.includes('ApexOrgWideCoverage')) return Promise.resolve(coverage === null ? [] : [{ PercentCovered: coverage }]);
    return Promise.resolve([{ cnt: 3 }]);
  });
  return {
    soql: {} as any,
    tooling: { query } as any,
    rest: {} as any,
    orgInfo: { id: '00Dxx0000000000EAA', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://acme.my.salesforce.com' },
    cache: { apexBodies: [] } as any,
  } as any;
}

describe('CodeSecurityCheck code coverage', () => {
  const check = new CodeSecurityCheck();
  const coverageFinding = async (pct: number | null) =>
    (await check.run(makeCtx(pct))).findings.find((f) => f.id.startsWith('code-coverage'))!;

  // Coverage is a deployment gate and a quality measure, not a security control.
  it.each([
    [60, 'MEDIUM'],
    [74, 'MEDIUM'],
    [75, 'LOW'],
    [84, 'LOW'],
    [95, 'LOW'],
  ])('reports %d%% as %s', async (pct, level) => {
    const f = await coverageFinding(pct);
    expect(f.id).toBe('code-coverage');
    expect(f.riskLevel).toBe(level);
  });

  it('says what coverage does and does not measure', async () => {
    expect((await coverageFinding(60)).detail).toMatch(/not whether the code is secure/);
  });

  it('is INFO when no coverage data exists', async () => {
    const f = await coverageFinding(null);
    expect(f).toMatchObject({ id: 'code-coverage-unavailable', riskLevel: 'INFO' });
  });
});
