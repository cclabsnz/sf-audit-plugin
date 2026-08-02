import { SeparationOfDutiesCheck } from '../../../../src/checks/impl/SeparationOfDutiesCheck.js';
import type { AuditContext } from '@cclabsnz/sf-core';
import type { EffectivePermissionGrant } from '@cclabsnz/sf-core';

function makeCtx(grants?: EffectivePermissionGrant[]): AuditContext {
  return {
    soql: {} as any,
    tooling: {} as any,
    rest: {} as any,
    orgInfo: { id: 'o', name: 'n', type: 'DE', isSandbox: false, instance: 'NA1', instanceUrl: 'https://x' },
    cache: { effectivePermissions: grants } as any,
  } as any;
}

const grant = (username: string, perms: string[], profileName = 'Standard'): EffectivePermissionGrant => ({
  userId: username, username, name: username, profileName, perms,
});

describe('SeparationOfDutiesCheck', () => {
  const check = new SeparationOfDutiesCheck();

  it('flags Manage Users + Assign Permission Sets as a CRITICAL self-escalation combo', async () => {
    const ctx = makeCtx([grant('u@x.com', ['ManageUsers', 'AssignPermissionSets'])]);
    const result = await check.run(ctx);
    const f = result.findings.find((x) => x.id === 'separation-of-duties-self-escalation');
    expect(f).toBeDefined();
    expect(f!.riskLevel).toBe('CRITICAL');
  });

  it('flags Author Apex + Modify All Data', async () => {
    const ctx = makeCtx([grant('dev@x.com', ['AuthorApex', 'ModifyAllData'])]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'separation-of-duties-code-and-data')).toBe(true);
  });

  it('does not fire when a user holds only one half of a combo', async () => {
    const ctx = makeCtx([grant('u@x.com', ['ManageUsers'])]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'separation-of-duties-ok' && f.passed)).toBe(true);
  });

  it('passes when there are no privileged users at all', async () => {
    const ctx = makeCtx([]);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.id === 'separation-of-duties-ok' && f.passed)).toBe(true);
  });

  it('is inconclusive when the effective-permission cache is missing', async () => {
    const ctx = makeCtx(undefined);
    const result = await check.run(ctx);
    expect(result.findings.some((f) => f.inconclusive)).toBe(true);
  });
});
