import { jest } from '@jest/globals';
import { GuestExecutableApexCheck } from '../../../../src/checks/impl/GuestExecutableApexCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';

interface Mocks { guestUsers: unknown[]; setupAccess: unknown[]; apexNames: unknown[]; }

function makeCtx(m: Mocks, apexBodies?: Array<{ name: string; body: string }>): AuditContext {
  const soqlQueryAll = jest.fn() as any;
  soqlQueryAll
    .mockResolvedValueOnce(m.guestUsers)   // guest users
    .mockResolvedValueOnce(m.setupAccess); // SetupEntityAccess
  const toolingQuery = jest.fn() as any;
  toolingQuery.mockResolvedValue(m.apexNames); // ApexClass id→name
  return {
    soql: { query: jest.fn(), queryAll: soqlQueryAll } as any,
    tooling: { query: toolingQuery, getRecord: jest.fn() } as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: apexBodies ? { apexBodies } : {},
  } as any;
}

describe('GuestExecutableApexCheck', () => {
  const check = new GuestExecutableApexCheck();

  it('passes when there are no guest users', async () => {
    const ctx = makeCtx({ guestUsers: [], setupAccess: [], apexNames: [] });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'guest-executable-apex-none' && f.passed)).toBe(true);
  });

  it('flags an unprotected (without sharing) guest-executable class as CRITICAL', async () => {
    const ctx = makeCtx(
      {
        guestUsers: [{ Id: '005g', ProfileId: '00eP', Username: 'guest@site' }],
        setupAccess: [{ SetupEntityId: '01pA', ParentId: '00eP' }],
        apexNames: [{ Id: '01pA', Name: 'PublicController' }],
      },
      [{ name: 'PublicController', body: 'public without sharing class PublicController { void f(){ [SELECT Id FROM Account]; } }' }],
    );
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'guest-executable-apex-unprotected');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
    expect(f!.affectedItems?.[0].label).toContain('PublicController');
  });

  it('flags guest-executable classes (no body available) as HIGH exposed', async () => {
    const ctx = makeCtx({
      guestUsers: [{ Id: '005g', ProfileId: '00eP', Username: 'guest@site' }],
      setupAccess: [{ SetupEntityId: '01pA', ParentId: '00eP' }],
      apexNames: [{ Id: '01pA', Name: 'SomeController' }],
    });
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'guest-executable-apex-exposed');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('HIGH');
  });

  it('passes when guests can execute no Apex classes', async () => {
    const ctx = makeCtx({
      guestUsers: [{ Id: '005g', ProfileId: '00eP', Username: 'guest@site' }],
      setupAccess: [],
      apexNames: [],
    });
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'guest-executable-apex-ok' && f.passed)).toBe(true);
  });
});
